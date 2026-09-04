/*
 * generate_boundary_rr_corpus.c
 *
 * Generates a small, hand-crafted seed corpus of raw DNS response packets,
 * each stressing the "attacker-controlled length field copied into a
 * fixed-size local stack buffer" pattern that caused the APL (TYPE 42)
 * stack-buffer-overflow in tools/dag.c's format_rdata_for_display().
 *
 * These are not meant to replace fuzzing; they are deterministic,
 * human-auditable regression seeds for:
 *   - tests/fuzz/fuzz_dag_response   (print_response / print_rdata path)
 *   - tests/fuzz/fuzz_dag_hash       (calculate_packet_hashes /
 *                                     format_rdata_for_display path -- the
 *                                     path where the APL bug actually lived)
 *
 * Usage:
 *   cc -O2 -o generate_boundary_rr_corpus tests/fuzz/generate_boundary_rr_corpus.c
 *   ./generate_boundary_rr_corpus
 *   (writes files into tests/fuzz/corpus/boundary_*.bin)
 *
 * Each scenario targets a specific RR type / code path known (from manual
 * source review of tools/dag.c) to parse a variable-length subfield taken
 * from untrusted wire data. Where a fixed-size scratch buffer exists,
 * the length field is deliberately set beyond that buffer's size.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static uint8_t pkt[65535];
static size_t off;

static void reset(uint16_t qid, uint16_t ancount) {
    memset(pkt, 0, sizeof(pkt));
    off = 0;
    pkt[off++] = (uint8_t)(qid >> 8); pkt[off++] = (uint8_t)qid;
    pkt[off++] = 0x81; pkt[off++] = 0x80; // standard response, no error
    pkt[off++] = 0x00; pkt[off++] = 0x01; // QDCOUNT = 1
    pkt[off++] = (uint8_t)(ancount >> 8); pkt[off++] = (uint8_t)ancount;
    pkt[off++] = 0x00; pkt[off++] = 0x00; // NSCOUNT
    pkt[off++] = 0x00; pkt[off++] = 0x00; // ARCOUNT
}

static void put_name(const char *dotted) {
    const char *p = dotted;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        pkt[off++] = (uint8_t)len;
        memcpy(&pkt[off], p, len);
        off += len;
        p += len;
        if (dot) p++;
        else break;
    }
    pkt[off++] = 0x00;
}

static void put_u16(uint16_t v) { pkt[off++] = (uint8_t)(v >> 8); pkt[off++] = (uint8_t)v; }
static void put_u32(uint32_t v) {
    pkt[off++] = (uint8_t)(v >> 24); pkt[off++] = (uint8_t)(v >> 16);
    pkt[off++] = (uint8_t)(v >> 8);  pkt[off++] = (uint8_t)v;
}

static void write_pkt(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "tests/fuzz/corpus/boundary_%s.bin", name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    fwrite(pkt, 1, off, f);
    fclose(f);
    printf("wrote %s (%zu bytes)\n", path, off);
}

/* Question section shared by every scenario: qname APL/ANY IN */
static void put_question(const char *name, uint16_t qtype) {
    put_name(name);
    put_u16(qtype);
    put_u16(1); // IN
}

int main(void) {
    system("mkdir -p tests/fuzz/corpus");

    /* --- 1. APL (TYPE 42): afdlength=127, AFI=1 (the original bug) --- */
    {
        reset(0x0001, 1);
        put_question("apl-overflow.example", 42);
        put_name("apl-overflow.example");
        put_u16(42); put_u16(1); put_u32(300);
        uint16_t rdlen = 2 + 1 + 1 + 127;
        put_u16(rdlen);
        put_u16(1);      // AFI = 1 (IPv4)
        pkt[off++] = 0;  // prefix
        pkt[off++] = 0x7F; // N=0, afdlength=127 (max representable)
        memset(&pkt[off], 'A', 127); off += 127;
        write_pkt("apl_afi1_afdlen127");
    }

    /* --- 2. APL: afdlength=127, AFI=2 (IPv6, still overflows 16-byte addr[]) --- */
    {
        reset(0x0002, 1);
        put_question("apl-overflow.example", 42);
        put_name("apl-overflow.example");
        put_u16(42); put_u16(1); put_u32(300);
        uint16_t rdlen = 2 + 1 + 1 + 127;
        put_u16(rdlen);
        put_u16(2);
        pkt[off++] = 0;
        pkt[off++] = 0x7F;
        memset(&pkt[off], 'B', 127); off += 127;
        write_pkt("apl_afi2_afdlen127");
    }

    /* --- 3. APL: unassigned AFI (99), afdlength=127 --- */
    {
        reset(0x0003, 1);
        put_question("apl-overflow.example", 42);
        put_name("apl-overflow.example");
        put_u16(42); put_u16(1); put_u32(300);
        uint16_t rdlen = 2 + 1 + 1 + 127;
        put_u16(rdlen);
        put_u16(99);
        pkt[off++] = 0;
        pkt[off++] = 0x7F;
        memset(&pkt[off], 'C', 127); off += 127;
        write_pkt("apl_unknown_afi_afdlen127");
    }

    /* --- 4. APL: two elements back-to-back, second one malicious --- */
    {
        reset(0x0004, 1);
        put_question("apl-overflow.example", 42);
        put_name("apl-overflow.example");
        put_u16(42); put_u16(1); put_u32(300);
        uint16_t rdlen = (2+1+1+4) + (2+1+1+127);
        put_u16(rdlen);
        put_u16(1); pkt[off++] = 24; pkt[off++] = 4; // valid IPv4 element
        pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1;
        put_u16(1); pkt[off++] = 0; pkt[off++] = 0x7F; // malicious second element
        memset(&pkt[off], 'D', 127); off += 127;
        write_pkt("apl_multi_element_second_malicious");
    }

    /* --- 5. APL valid baseline (regression: must still print correctly) --- */
    {
        reset(0x0005, 1);
        put_question("apl-valid.example", 42);
        put_name("apl-valid.example");
        put_u16(42); put_u16(1); put_u32(300);
        put_u16(2+1+1+4);
        put_u16(1); pkt[off++] = 24; pkt[off++] = 4;
        pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1;
        write_pkt("apl_valid_baseline");
    }

    /* --- 6. SSHFP (TYPE 44) with rdlen < 2 (guards `rdlen >= 2`) --- */
    {
        reset(0x0006, 1);
        put_question("sshfp-short.example", 44);
        put_name("sshfp-short.example");
        put_u16(44); put_u16(1); put_u32(300);
        put_u16(1);
        pkt[off++] = 2; // only 1 byte of rdata present
        write_pkt("sshfp_rdlen_underflow");
    }

    /* --- 7. CERT (TYPE 37) with rdlen < 5 (guards `rdlen >= 5`) --- */
    {
        reset(0x0007, 1);
        put_question("cert-short.example", 37);
        put_name("cert-short.example");
        put_u16(37); put_u16(1); put_u32(300);
        put_u16(3);
        pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 1;
        write_pkt("cert_rdlen_underflow");
    }

    /* --- 8. CAA (TYPE 257) with tag_len pushing past rdlen --- */
    {
        reset(0x0008, 1);
        put_question("caa-overflow.example", 257);
        put_name("caa-overflow.example");
        put_u16(257); put_u16(1); put_u32(300);
        put_u16(3);
        pkt[off++] = 0;    // flags
        pkt[off++] = 0xFF; // tag_len = 255, but rdlen only allows for 1 more byte
        pkt[off++] = 'i';
        write_pkt("caa_taglen_overflow");
    }

    /* --- 9. DHCID (TYPE 49) with rdlen = 0 --- */
    {
        reset(0x0009, 1);
        put_question("dhcid-short.example", 49);
        put_name("dhcid-short.example");
        put_u16(49); put_u16(1); put_u32(300);
        put_u16(0);
        write_pkt("dhcid_rdlen_zero");
    }

    /* --- 10. TSIG (TYPE 250) with mac_size claiming far more than rdlen allows --- */
    {
        reset(0x000A, 1);
        put_question("tsig-overflow.example", 250);
        put_name("tsig-overflow.example");
        /* algorithm name (hmac-sha256.) */
        size_t name_start = off;
        put_name("hmac-sha256");
        (void)name_start;
        put_u16(250); put_u16(255); /* class ANY per RFC 8945 */
        put_u32(0); /* TTL = 0 */
        size_t rdlen_pos = off;
        put_u16(0); /* placeholder, fixed below */
        size_t rdata_start = off;
        put_u16(0); put_u32(0); /* time_signed (48-bit split across two writes below is wrong; keep simple) */
        put_u16(300); /* fudge */
        put_u16(0xFFFF); /* mac_size = 65535, wildly exceeds remaining rdlen */
        pkt[off++] = 'X'; /* only 1 byte of "mac" actually present */
        uint16_t rdlen = (uint16_t)(off - rdata_start);
        pkt[rdlen_pos] = (uint8_t)(rdlen >> 8); pkt[rdlen_pos+1] = (uint8_t)rdlen;
        write_pkt("tsig_macsize_overflow");
    }

    /* --- 11. IPSECKEY (TYPE 45) gateway type 3 (domain name) truncated --- */
    {
        reset(0x000B, 1);
        put_question("ipseckey-short.example", 45);
        put_name("ipseckey-short.example");
        put_u16(45); put_u16(1); put_u32(300);
        put_u16(3);
        pkt[off++] = 10; /* precedence */
        pkt[off++] = 3;  /* gateway type = domain name */
        pkt[off++] = 8;  /* algorithm */
        /* rdlen only covers the 3 fixed bytes; the domain-name gateway is
         * entirely missing, forcing the parser down its truncated-RDATA
         * handling path. */
        write_pkt("ipseckey_gw3_truncated");
    }

    /* --- 12. NSEC (TYPE 47) with an oversized type-bitmap window length --- */
    {
        reset(0x000C, 1);
        put_question("nsec-overflow.example", 47);
        put_name("nsec-overflow.example");
        put_u16(47); put_u16(1); put_u32(300);
        size_t rdlen_pos_2 = off; put_u16(0);
        size_t rdata_start_2 = off;
        put_name("next.nsec-overflow.example");
        pkt[off++] = 0;    // window block 0
        pkt[off++] = 0xFF; // claims 255 bytes of bitmap, but far fewer remain
        pkt[off++] = 0x03;
        uint16_t rdlen2 = (uint16_t)(off - rdata_start_2);
        pkt[rdlen_pos_2] = (uint8_t)(rdlen2 >> 8); pkt[rdlen_pos_2+1] = (uint8_t)rdlen2;
        write_pkt("nsec_bitmap_len_overflow");
    }

    /* --- 13. HTTPS/SVCB (TYPE 65) with an oversized SvcParamValue length --- */
    {
        reset(0x000D, 1);
        put_question("https-overflow.example", 65);
        put_name("https-overflow.example");
        put_u16(65); put_u16(1); put_u32(300);
        size_t rdlen_pos_3 = off; put_u16(0);
        size_t rdata_start_3 = off;
        put_u16(1);       // SvcPriority
        pkt[off++] = 0;   // TargetName = root
        put_u16(1);       // SvcParamKey = alpn
        put_u16(0xFFFF);  // SvcParamValue length, wildly exceeds rdlen
        pkt[off++] = 2; pkt[off++] = 'h'; pkt[off++] = '2';
        uint16_t rdlen3 = (uint16_t)(off - rdata_start_3);
        pkt[rdlen_pos_3] = (uint8_t)(rdlen3 >> 8); pkt[rdlen_pos_3+1] = (uint8_t)rdlen3;
        write_pkt("https_svcparam_len_overflow");
    }

    /* --- 14. OPT/EDNS Client Subnet (ECS) option with oversized address --- */
    {
        reset(0x000E, 0);
        put_question("ecs-overflow.example", 1);
        pkt[7] = 0; /* ANCOUNT = 0 */
        pkt[11] = 1; /* ARCOUNT = 1: just the OPT RR */
        put_name(""); /* root name for OPT */
        put_u16(41);    // TYPE OPT
        put_u16(4096);  // "CLASS" = UDP payload size
        put_u32(0);     // extended rcode/flags
        size_t rdlen_pos_4 = off; put_u16(0);
        size_t rdata_start_4 = off;
        put_u16(8); // option code = 8 (ECS)
        put_u16(20); // option length claims 20 bytes of address data
        put_u16(1);  // family = IPv4
        pkt[off++] = 32; // source prefix
        pkt[off++] = 0;  // scope prefix
        memset(&pkt[off], 0xAA, 17); off += 17; // only 17 of the claimed 20 bytes present
        uint16_t rdlen4 = (uint16_t)(off - rdata_start_4);
        pkt[rdlen_pos_4] = (uint8_t)(rdlen4 >> 8); pkt[rdlen_pos_4+1] = (uint8_t)rdlen4;
        write_pkt("ecs_option_len_overflow");
    }

    printf("done.\n");
    return 0;
}
