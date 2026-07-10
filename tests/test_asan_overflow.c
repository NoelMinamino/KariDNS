#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../dns_wire.h"
#include "../dns_config_parser.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}


static int assert_bound_checked(dns_record_t *rec) {
    uint8_t big_buf[4096];
    uint16_t off1 = 0;
    compress_ctx_t c1; compress_ctx_init_packet(&c1);
    if (serialize_dns_record(big_buf, sizeof(big_buf), &off1, rec, &c1, NULL, 0) != 0) {
        printf("Bound-check test setup failed: type %u did not succeed with generous buffer\n", rec->type_code);
        return 1;
    }
    uint8_t small_buf[4096];
    uint16_t off2 = 0;
    compress_ctx_t c2; compress_ctx_init_packet(&c2);
    if (serialize_dns_record(small_buf, off1 - 1, &off2, rec, &c2, NULL, 0) != -1) {
        printf("Bound-check test FAILED: type %u succeeded with max_res_len=%u-1 (should have failed)\n", rec->type_code, off1);
        return 1;
    }
    return 0;
}

int main() {
    server_config_t cfg;
    
    // Test 1: 340 characters (accepted)
    memset(&cfg, 0, sizeof(cfg));
    char conf_340[1024];
    strcpy(conf_340, "key \"test\" { algorithm hmac-sha256; secret \"");
    for(int i=0; i<340; i++) strcat(conf_340, "A");
    strcat(conf_340, "\"; };");
    char* copy_340 = strdup(conf_340);
    int res1 = parse_named_conf(copy_340, &cfg);
    free(copy_340);
    if (res1 == 0) {
        printf("Test 1 Passed: Accepted 340 char secret\n");
    } else {
        printf("Test 1 Failed: Rejected 340 char secret!\n");
        return 1;
    }

    // Test 2: 344 characters (rejected)
    memset(&cfg, 0, sizeof(cfg));
    char conf_344[1024];
    strcpy(conf_344, "key \"test\" { algorithm hmac-sha256; secret \"");
    for(int i=0; i<344; i++) strcat(conf_344, "A");
    strcat(conf_344, "\"; };");
    char* copy_344 = strdup(conf_344);
    int res2 = parse_named_conf(copy_344, &cfg);
    free(copy_344);
    if (res2 == -1) {
        printf("Test 2 Passed: Rejected 344 char secret\n");
    } else {
        printf("Test 2 Failed: Accepted 344 char secret!\n");
        return 1;
    }
    
    // Test 3: New record types boundary checks
    {
        uint8_t packet[20];
        uint16_t offset = 0;
        compress_ctx_t ctx;
        compress_ctx_init_packet(&ctx);

        // SSHFP
        dns_record_t rec_sshfp = {0};
        rec_sshfp.name = (char*)"example.com"; rec_sshfp.type_code = 44; rec_sshfp.rdata_count = 3;
        rec_sshfp.rdata[0] = (char*)"2"; rec_sshfp.rdata[1] = (char*)"1"; rec_sshfp.rdata[2] = (char*)"1234567890abcdef";
        if (assert_bound_checked(&rec_sshfp)) return 1;
        
        // TLSA
        dns_record_t rec_tlsa = {0};
        rec_tlsa.name = (char*)"_443._tcp.example.com"; rec_tlsa.type_code = 52; rec_tlsa.rdata_count = 4;
        rec_tlsa.rdata[0] = (char*)"3"; rec_tlsa.rdata[1] = (char*)"1"; rec_tlsa.rdata[2] = (char*)"1"; rec_tlsa.rdata[3] = (char*)"abcdef";
        if (assert_bound_checked(&rec_tlsa)) return 1;

        // CERT
        dns_record_t rec_cert = {0};
        rec_cert.name = (char*)"example.com"; rec_cert.type_code = 37; rec_cert.rdata_count = 4;
        rec_cert.rdata[0] = (char*)"PKIX"; rec_cert.rdata[1] = (char*)"12345"; rec_cert.rdata[2] = (char*)"8"; 
        rec_cert.rdata[3] = (char*)"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        if (assert_bound_checked(&rec_cert)) return 1;

        // NAPTR
        dns_record_t rec_naptr = {0};
        rec_naptr.name = (char*)"example.com"; rec_naptr.type_code = 35; rec_naptr.rdata_count = 6;
        rec_naptr.rdata[0] = (char*)"100"; rec_naptr.rdata[1] = (char*)"10"; rec_naptr.rdata[2] = (char*)"S";
        rec_naptr.rdata[3] = (char*)"SIP+D2U"; rec_naptr.rdata[4] = (char*)""; rec_naptr.rdata[5] = (char*)"_sip._udp.example.com.";
        if (assert_bound_checked(&rec_naptr)) return 1;

        // NSEC3PARAM
        dns_record_t rec_nsec3param = {0};
        rec_nsec3param.name = (char*)"example.com"; rec_nsec3param.type_code = 51; rec_nsec3param.rdata_count = 4;
        rec_nsec3param.rdata[0] = (char*)"1"; rec_nsec3param.rdata[1] = (char*)"0"; rec_nsec3param.rdata[2] = (char*)"10";
        rec_nsec3param.rdata[3] = (char*)"12345678";
        if (assert_bound_checked(&rec_nsec3param)) return 1;

  
        // HINFO
        dns_record_t rec_hinfo = {0};
        rec_hinfo.name = (char*)"example.com"; rec_hinfo.type_code = 13; rec_hinfo.rdata_count = 2;
        rec_hinfo.rdata[0] = (char*)"INTEL-386"; rec_hinfo.rdata[1] = (char*)"UNIX";
        if (assert_bound_checked(&rec_hinfo)) return 1;

        // URI
        dns_record_t rec_uri = {0};
        rec_uri.name = (char*)"example.com"; rec_uri.type_code = 256; rec_uri.rdata_count = 3;
        rec_uri.rdata[0] = (char*)"10"; rec_uri.rdata[1] = (char*)"1"; rec_uri.rdata[2] = (char*)"ftp://ftp.example.com/public";
        if (assert_bound_checked(&rec_uri)) return 1;

        // OPENPGPKEY
        dns_record_t rec_openpgpkey = {0};
        rec_openpgpkey.name = (char*)"example.com"; rec_openpgpkey.type_code = 61; rec_openpgpkey.rdata_count = 1;
        rec_openpgpkey.rdata[0] = (char*)"mQENBFxJ0V4BCADA"; // Dummy base64 string
        if (assert_bound_checked(&rec_openpgpkey)) return 1;

        // DHCID
        dns_record_t rec_dhcid = {0};
        rec_dhcid.name = (char*)"example.com"; rec_dhcid.type_code = 49; rec_dhcid.rdata_count = 1;
        rec_dhcid.rdata[0] = (char*)"AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=";
        if (assert_bound_checked(&rec_dhcid)) return 1;

        // EUI48
        dns_record_t rec_eui48 = {0};
        rec_eui48.name = (char*)"example.com"; rec_eui48.type_code = 108; rec_eui48.rdata_count = 1;
        rec_eui48.rdata[0] = (char*)"00-11-22-33-44-55";
        if (assert_bound_checked(&rec_eui48)) return 1;

        // EUI64
        dns_record_t rec_eui64 = {0};
        rec_eui64.name = (char*)"example.com"; rec_eui64.type_code = 109; rec_eui64.rdata_count = 1;
        rec_eui64.rdata[0] = (char*)"00-11-22-33-44-55-66-77";
        if (assert_bound_checked(&rec_eui64)) return 1;

        // ZONEMD
        dns_record_t rec_zonemd = {0};
        rec_zonemd.name = (char*)"example.com"; rec_zonemd.type_code = 63; rec_zonemd.rdata_count = 4;
        rec_zonemd.rdata[0] = (char*)"2018031500"; rec_zonemd.rdata[1] = (char*)"1"; rec_zonemd.rdata[2] = (char*)"1";
        rec_zonemd.rdata[3] = (char*)"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
        if (assert_bound_checked(&rec_zonemd)) return 1;

        // MINFO
        dns_record_t rec_minfo = {0};
        rec_minfo.name = (char*)"example.com"; rec_minfo.type_code = 14; rec_minfo.rdata_count = 2;
        rec_minfo.rdata[0] = (char*)"rm.example.com"; rec_minfo.rdata[1] = (char*)"err.example.com";
        if (assert_bound_checked(&rec_minfo)) return 1;

        // RP
        dns_record_t rec_rp = {0};
        rec_rp.name = (char*)"example.com"; rec_rp.type_code = 17; rec_rp.rdata_count = 2;
        rec_rp.rdata[0] = (char*)"admin.example.com"; rec_rp.rdata[1] = (char*)"txt.example.com";
        if (assert_bound_checked(&rec_rp)) return 1;

        // AFSDB
        dns_record_t rec_afsdb = {0};
        rec_afsdb.name = (char*)"example.com"; rec_afsdb.type_code = 18; rec_afsdb.rdata_count = 2;
        rec_afsdb.rdata[0] = (char*)"1"; rec_afsdb.rdata[1] = (char*)"afs.example.com";
        if (assert_bound_checked(&rec_afsdb)) return 1;

        // KX
        dns_record_t rec_kx = {0};
        rec_kx.name = (char*)"example.com"; rec_kx.type_code = 36; rec_kx.rdata_count = 2;
        rec_kx.rdata[0] = (char*)"10"; rec_kx.rdata[1] = (char*)"kx.example.com";
        if (assert_bound_checked(&rec_kx)) return 1;

        // PX
        dns_record_t rec_px = {0};
        rec_px.name = (char*)"example.com"; rec_px.type_code = 26; rec_px.rdata_count = 3;
        rec_px.rdata[0] = (char*)"10"; rec_px.rdata[1] = (char*)"px1.example.com"; rec_px.rdata[2] = (char*)"px2.example.com";
        if (assert_bound_checked(&rec_px)) return 1;

        // RT
        dns_record_t rec_rt = {0};
        rec_rt.name = (char*)"example.com"; rec_rt.type_code = 21; rec_rt.rdata_count = 2;
        rec_rt.rdata[0] = (char*)"10"; rec_rt.rdata[1] = (char*)"rt.example.com";
        if (assert_bound_checked(&rec_rt)) return 1;

        // LP
        dns_record_t rec_lp = {0};
        rec_lp.name = (char*)"example.com"; rec_lp.type_code = 107; rec_lp.rdata_count = 2;
        rec_lp.rdata[0] = (char*)"10"; rec_lp.rdata[1] = (char*)"lp.example.com";
        if (assert_bound_checked(&rec_lp)) return 1;

        // CSYNC
        dns_record_t rec_csync = {0};
        rec_csync.name = (char*)"example.com"; rec_csync.type_code = 62; rec_csync.rdata_count = 4;
        rec_csync.rdata[0] = (char*)"123456"; rec_csync.rdata[1] = (char*)"1"; rec_csync.rdata[2] = (char*)"A"; rec_csync.rdata[3] = (char*)"AAAA";
        if (assert_bound_checked(&rec_csync)) return 1;
      printf("Test 3 Passed: All new records safely rejected small max_res_len\n");
    }

    // Test 4: Local buffer overflow prevention (Input boundary checks)
    {
        uint8_t packet[2048]; // Large enough to hold valid packets
        uint16_t offset = 0;
        compress_ctx_t ctx;
        compress_ctx_init_packet(&ctx);

        char huge_hex[1100];
        char huge_b64[1100];
        for(int i=0; i<1099; i++) { huge_hex[i] = 'A'; huge_b64[i] = 'A'; }
        huge_hex[1099] = '\0';
        huge_b64[1099] = '\0';
        
        static char exact_hex_512[1025];
        for (int i=0; i<1024; i++) exact_hex_512[i] = 'A';
        exact_hex_512[1024] = '\0';


        // TLSA (Type 52) - exact hex string for bound checking
        dns_record_t rec_tlsa = {0};
        rec_tlsa.name = (char*)"_443._tcp.example.com"; rec_tlsa.type_code = 52; rec_tlsa.rdata_count = 4;
        rec_tlsa.rdata[0] = (char*)"3"; rec_tlsa.rdata[1] = (char*)"1"; rec_tlsa.rdata[2] = (char*)"1"; 
        rec_tlsa.rdata[3] = exact_hex_512;
        if (assert_bound_checked(&rec_tlsa)) return 1;

        // TLSA: hex_decode's local buffer (cad[512]) overflow test
        {
            uint8_t packet[2048];
            uint16_t offset = 0;
            compress_ctx_t ctx; compress_ctx_init_packet(&ctx);
            dns_record_t rec_tlsa_overflow = {0};
            rec_tlsa_overflow.name = (char*)"_443._tcp.example.com";
            rec_tlsa_overflow.type_code = 52; rec_tlsa_overflow.rdata_count = 4;
            rec_tlsa_overflow.rdata[0] = (char*)"3"; rec_tlsa_overflow.rdata[1] = (char*)"1";
            rec_tlsa_overflow.rdata[2] = (char*)"1"; rec_tlsa_overflow.rdata[3] = huge_hex;
            if (serialize_dns_record(packet, 2048, &offset, &rec_tlsa_overflow, &ctx, NULL, 0) != -1) {
                printf("Test 4 Failed: TLSA local-buffer overflow (hex_decode) did not fail\n"); return 1;
            }
        }

        // CERT (Type 37) - huge base64 string
        // Note: The following test with huge_b64 actually tests EVP_DecodeBlock rejecting
        // invalid base64 lengths rather than the bound check itself.
        dns_record_t rec_cert = {0};
        rec_cert.name = (char*)"example.com"; rec_cert.type_code = 37; rec_cert.rdata_count = 4;
        rec_cert.rdata[0] = (char*)"PKIX"; rec_cert.rdata[1] = (char*)"12345"; rec_cert.rdata[2] = (char*)"8"; 
        rec_cert.rdata[3] = huge_b64;
        // Since huge_b64 has 1099 chars, (1099/4)*3 = 822. offset=13+10+12=35. Total 857.
        // The generous buffer will pass length check, but EVP_DecodeBlock will return -1
        // because 1099 is not a valid base64 length. So serialize_dns_record returns -1.
        // assert_bound_checked expects generous buffer to return 0. So we can't use it here.
        // We do it manually:
        {
            uint8_t packet[2048];
            uint16_t offset = 0;
            compress_ctx_t ctx; compress_ctx_init_packet(&ctx);
            if (serialize_dns_record(packet, 2048, &offset, &rec_cert, &ctx, NULL, 0) != -1) {
                printf("Test 4 Failed: CERT with invalid base64 length did not fail\n"); return 1;
            }
        }

        // CERT: Valid Base64 that exceeds max_res_len (boundary check test)
        dns_record_t rec_cert2 = {0};
        rec_cert2.name = (char*)"example.com"; rec_cert2.type_code = 37; rec_cert2.rdata_count = 4;
        rec_cert2.rdata[0] = (char*)"PKIX"; rec_cert2.rdata[1] = (char*)"12345"; rec_cert2.rdata[2] = (char*)"8";
        
        static char valid_long_b64[1101];
        for (int i = 0; i < 275; i++) memcpy(valid_long_b64 + i*4, "AAAA", 4);
        valid_long_b64[1100] = '\0';
        rec_cert2.rdata[3] = valid_long_b64;
        
        // max_res_len is intentionally small to trigger 'decoded_upper_bound > max_res_len'
        if (assert_bound_checked(&rec_cert2)) return 1;

        // ZONEMD (Type 63) - exact hex string for bound checking
        dns_record_t rec_zonemd = {0};
        rec_zonemd.name = (char*)"example.com"; rec_zonemd.type_code = 63; rec_zonemd.rdata_count = 4;
        rec_zonemd.rdata[0] = (char*)"2018031500"; rec_zonemd.rdata[1] = (char*)"1"; rec_zonemd.rdata[2] = (char*)"1";
        rec_zonemd.rdata[3] = exact_hex_512;
        if (assert_bound_checked(&rec_zonemd)) return 1;

        // ZONEMD: hex_decode's local buffer (digest[512]) overflow test
        {
            uint8_t packet[2048];
            uint16_t offset = 0;
            compress_ctx_t ctx; compress_ctx_init_packet(&ctx);
            dns_record_t rec_zonemd_overflow = {0};
            rec_zonemd_overflow.name = (char*)"example.com";
            rec_zonemd_overflow.type_code = 63; rec_zonemd_overflow.rdata_count = 4;
            rec_zonemd_overflow.rdata[0] = (char*)"2018031500"; rec_zonemd_overflow.rdata[1] = (char*)"1";
            rec_zonemd_overflow.rdata[2] = (char*)"1"; rec_zonemd_overflow.rdata[3] = huge_hex;
            if (serialize_dns_record(packet, 2048, &offset, &rec_zonemd_overflow, &ctx, NULL, 0) != -1) {
                printf("Test 4 Failed: ZONEMD local-buffer overflow (hex_decode) did not fail\n"); return 1;
            }
        }

        // NID (Type 104)
        dns_record_t rec_nid = {0};
        rec_nid.name = (char*)"example.com"; rec_nid.type_code = 104; rec_nid.rdata_count = 2;
        rec_nid.rdata[0] = (char*)"10"; rec_nid.rdata[1] = (char*)"0000:0000:0000:0000";
        if (assert_bound_checked(&rec_nid)) return 1;

        // L32 (Type 105)
        dns_record_t rec_l32 = {0};
        rec_l32.name = (char*)"example.com"; rec_l32.type_code = 105; rec_l32.rdata_count = 2;
        rec_l32.rdata[0] = (char*)"10"; rec_l32.rdata[1] = (char*)"192.0.2.1";
        if (assert_bound_checked(&rec_l32)) return 1;

        // L64 (Type 106)
        dns_record_t rec_l64 = {0};
        rec_l64.name = (char*)"example.com"; rec_l64.type_code = 106; rec_l64.rdata_count = 2;
        rec_l64.rdata[0] = (char*)"10"; rec_l64.rdata[1] = (char*)"0000:0000:0000:0000";
        if (assert_bound_checked(&rec_l64)) return 1;

        // IPSECKEY (Type 45) - GW Type 1 (IPv4)
        dns_record_t rec_ipseckey1 = {0};
        rec_ipseckey1.name = (char*)"example.com"; rec_ipseckey1.type_code = 45; rec_ipseckey1.rdata_count = 5;
        rec_ipseckey1.rdata[0] = (char*)"10"; rec_ipseckey1.rdata[1] = (char*)"1"; rec_ipseckey1.rdata[2] = (char*)"2";
        rec_ipseckey1.rdata[3] = (char*)"192.0.2.1"; rec_ipseckey1.rdata[4] = valid_long_b64;
        if (assert_bound_checked(&rec_ipseckey1)) return 1;

        // IPSECKEY (Type 45) - GW Type 2 (IPv6)
        dns_record_t rec_ipseckey2 = {0};
        rec_ipseckey2.name = (char*)"example.com"; rec_ipseckey2.type_code = 45; rec_ipseckey2.rdata_count = 5;
        rec_ipseckey2.rdata[0] = (char*)"10"; rec_ipseckey2.rdata[1] = (char*)"2"; rec_ipseckey2.rdata[2] = (char*)"2";
        rec_ipseckey2.rdata[3] = (char*)"2001:db8::1"; rec_ipseckey2.rdata[4] = valid_long_b64;
        if (assert_bound_checked(&rec_ipseckey2)) return 1;

        // IPSECKEY (Type 45) - GW Type 3 (Domain Name)
        dns_record_t rec_ipseckey3 = {0};
        rec_ipseckey3.name = (char*)"example.com"; rec_ipseckey3.type_code = 45; rec_ipseckey3.rdata_count = 5;
        rec_ipseckey3.rdata[0] = (char*)"10"; rec_ipseckey3.rdata[1] = (char*)"3"; rec_ipseckey3.rdata[2] = (char*)"2";
        rec_ipseckey3.rdata[3] = (char*)"gw.example.com"; rec_ipseckey3.rdata[4] = valid_long_b64;
        if (assert_bound_checked(&rec_ipseckey3)) return 1;

        // AMTRELAY (Type 260) - Type 1 (IPv4)
        dns_record_t rec_amtrelay1 = {0};
        rec_amtrelay1.name = (char*)"example.com"; rec_amtrelay1.type_code = 260; rec_amtrelay1.rdata_count = 4;
        rec_amtrelay1.rdata[0] = (char*)"10"; rec_amtrelay1.rdata[1] = (char*)"0"; rec_amtrelay1.rdata[2] = (char*)"1";
        rec_amtrelay1.rdata[3] = (char*)"192.0.2.1";
        if (assert_bound_checked(&rec_amtrelay1)) return 1;

        printf("Test 4 Passed: All input bound overflow tests safely rejected\n");
    }

    printf("All tests passed safely.\n");
    return 0;
}
