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
        if (serialize_dns_record(packet, 20, &offset, &rec_sshfp, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: SSHFP did not fail\n"); return 1;
        }
        
        // TLSA
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_tlsa = {0};
        rec_tlsa.name = (char*)"_443._tcp.example.com"; rec_tlsa.type_code = 52; rec_tlsa.rdata_count = 4;
        rec_tlsa.rdata[0] = (char*)"3"; rec_tlsa.rdata[1] = (char*)"1"; rec_tlsa.rdata[2] = (char*)"1"; rec_tlsa.rdata[3] = (char*)"abcdef";
        if (serialize_dns_record(packet, 20, &offset, &rec_tlsa, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: TLSA did not fail\n"); return 1;
        }

        // CERT
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_cert = {0};
        rec_cert.name = (char*)"example.com"; rec_cert.type_code = 37; rec_cert.rdata_count = 4;
        rec_cert.rdata[0] = (char*)"PKIX"; rec_cert.rdata[1] = (char*)"12345"; rec_cert.rdata[2] = (char*)"8"; 
        rec_cert.rdata[3] = (char*)"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        if (serialize_dns_record(packet, 20, &offset, &rec_cert, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: CERT did not fail\n"); return 1;
        }

        // NAPTR
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_naptr = {0};
        rec_naptr.name = (char*)"example.com"; rec_naptr.type_code = 35; rec_naptr.rdata_count = 6;
        rec_naptr.rdata[0] = (char*)"100"; rec_naptr.rdata[1] = (char*)"10"; rec_naptr.rdata[2] = (char*)"S";
        rec_naptr.rdata[3] = (char*)"SIP+D2U"; rec_naptr.rdata[4] = (char*)""; rec_naptr.rdata[5] = (char*)"_sip._udp.example.com.";
        if (serialize_dns_record(packet, 20, &offset, &rec_naptr, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: NAPTR did not fail\n"); return 1;
        }

        // NSEC3PARAM
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_nsec3param = {0};
        rec_nsec3param.name = (char*)"example.com"; rec_nsec3param.type_code = 51; rec_nsec3param.rdata_count = 4;
        rec_nsec3param.rdata[0] = (char*)"1"; rec_nsec3param.rdata[1] = (char*)"0"; rec_nsec3param.rdata[2] = (char*)"10";
        rec_nsec3param.rdata[3] = (char*)"12345678";
        if (serialize_dns_record(packet, 20, &offset, &rec_nsec3param, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: NSEC3PARAM did not fail\n"); return 1;
        }

  
        // HINFO
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_hinfo = {0};
        rec_hinfo.name = (char*)"example.com"; rec_hinfo.type_code = 13; rec_hinfo.rdata_count = 2;
        rec_hinfo.rdata[0] = (char*)"INTEL-386"; rec_hinfo.rdata[1] = (char*)"UNIX";
        if (serialize_dns_record(packet, 20, &offset, &rec_hinfo, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: HINFO did not fail\n"); return 1;
        }

        // URI
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_uri = {0};
        rec_uri.name = (char*)"example.com"; rec_uri.type_code = 256; rec_uri.rdata_count = 3;
        rec_uri.rdata[0] = (char*)"10"; rec_uri.rdata[1] = (char*)"1"; rec_uri.rdata[2] = (char*)"ftp://ftp.example.com/public";
        if (serialize_dns_record(packet, 20, &offset, &rec_uri, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: URI did not fail\n"); return 1;
        }

        // OPENPGPKEY
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_openpgpkey = {0};
        rec_openpgpkey.name = (char*)"example.com"; rec_openpgpkey.type_code = 61; rec_openpgpkey.rdata_count = 1;
        rec_openpgpkey.rdata[0] = (char*)"mQENBFxJ0V4BCAD..."; // Dummy long string for overflow test
        if (serialize_dns_record(packet, 20, &offset, &rec_openpgpkey, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: OPENPGPKEY did not fail\n"); return 1;
        }

        // DHCID
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_dhcid = {0};
        rec_dhcid.name = (char*)"example.com"; rec_dhcid.type_code = 49; rec_dhcid.rdata_count = 1;
        rec_dhcid.rdata[0] = (char*)"AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=";
        if (serialize_dns_record(packet, 20, &offset, &rec_dhcid, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: DHCID did not fail\n"); return 1;
        }

        // EUI48
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_eui48 = {0};
        rec_eui48.name = (char*)"example.com"; rec_eui48.type_code = 108; rec_eui48.rdata_count = 1;
        rec_eui48.rdata[0] = (char*)"00-11-22-33-44-55";
        if (serialize_dns_record(packet, 17, &offset, &rec_eui48, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: EUI48 did not fail\n"); return 1;
        }

        // EUI64
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_eui64 = {0};
        rec_eui64.name = (char*)"example.com"; rec_eui64.type_code = 109; rec_eui64.rdata_count = 1;
        rec_eui64.rdata[0] = (char*)"00-11-22-33-44-55-66-77";
        if (serialize_dns_record(packet, 20, &offset, &rec_eui64, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: EUI64 did not fail\n"); return 1;
        }

        // ZONEMD
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_zonemd = {0};
        rec_zonemd.name = (char*)"example.com"; rec_zonemd.type_code = 63; rec_zonemd.rdata_count = 4;
        rec_zonemd.rdata[0] = (char*)"2018031500"; rec_zonemd.rdata[1] = (char*)"1"; rec_zonemd.rdata[2] = (char*)"1";
        rec_zonemd.rdata[3] = (char*)"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
        if (serialize_dns_record(packet, 20, &offset, &rec_zonemd, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: ZONEMD did not fail\n"); return 1;
        }

        // MINFO
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_minfo = {0};
        rec_minfo.name = (char*)"example.com"; rec_minfo.type_code = 14; rec_minfo.rdata_count = 2;
        rec_minfo.rdata[0] = (char*)"rm.example.com"; rec_minfo.rdata[1] = (char*)"err.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_minfo, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: MINFO did not fail\n"); return 1;
        }

        // RP
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_rp = {0};
        rec_rp.name = (char*)"example.com"; rec_rp.type_code = 17; rec_rp.rdata_count = 2;
        rec_rp.rdata[0] = (char*)"admin.example.com"; rec_rp.rdata[1] = (char*)"txt.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_rp, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: RP did not fail\n"); return 1;
        }

        // AFSDB
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_afsdb = {0};
        rec_afsdb.name = (char*)"example.com"; rec_afsdb.type_code = 18; rec_afsdb.rdata_count = 2;
        rec_afsdb.rdata[0] = (char*)"1"; rec_afsdb.rdata[1] = (char*)"afs.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_afsdb, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: AFSDB did not fail\n"); return 1;
        }

        // KX
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_kx = {0};
        rec_kx.name = (char*)"example.com"; rec_kx.type_code = 36; rec_kx.rdata_count = 2;
        rec_kx.rdata[0] = (char*)"10"; rec_kx.rdata[1] = (char*)"kx.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_kx, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: KX did not fail\n"); return 1;
        }

        // PX
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_px = {0};
        rec_px.name = (char*)"example.com"; rec_px.type_code = 26; rec_px.rdata_count = 3;
        rec_px.rdata[0] = (char*)"10"; rec_px.rdata[1] = (char*)"px1.example.com"; rec_px.rdata[2] = (char*)"px2.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_px, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: PX did not fail\n"); return 1;
        }

        // RT
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_rt = {0};
        rec_rt.name = (char*)"example.com"; rec_rt.type_code = 21; rec_rt.rdata_count = 2;
        rec_rt.rdata[0] = (char*)"10"; rec_rt.rdata[1] = (char*)"rt.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_rt, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: RT did not fail\n"); return 1;
        }

        // LP
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_lp = {0};
        rec_lp.name = (char*)"example.com"; rec_lp.type_code = 107; rec_lp.rdata_count = 2;
        rec_lp.rdata[0] = (char*)"10"; rec_lp.rdata[1] = (char*)"lp.example.com";
        if (serialize_dns_record(packet, 20, &offset, &rec_lp, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: LP did not fail\n"); return 1;
        }

        // CSYNC
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_csync = {0};
        rec_csync.name = (char*)"example.com"; rec_csync.type_code = 62; rec_csync.rdata_count = 4;
        rec_csync.rdata[0] = (char*)"123456"; rec_csync.rdata[1] = (char*)"1"; rec_csync.rdata[2] = (char*)"A"; rec_csync.rdata[3] = (char*)"AAAA";
        if (serialize_dns_record(packet, 20, &offset, &rec_csync, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: CSYNC did not fail\n"); return 1;
        }
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

        // TLSA (Type 52) - huge hex string
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_tlsa = {0};
        rec_tlsa.name = (char*)"_443._tcp.example.com"; rec_tlsa.type_code = 52; rec_tlsa.rdata_count = 4;
        rec_tlsa.rdata[0] = (char*)"3"; rec_tlsa.rdata[1] = (char*)"1"; rec_tlsa.rdata[2] = (char*)"1"; 
        rec_tlsa.rdata[3] = huge_hex;
        if (serialize_dns_record(packet, 2048, &offset, &rec_tlsa, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: TLSA with huge hex did not fail\n"); return 1;
        }

        // CERT (Type 37) - huge base64 string
        // Note: The following test with huge_b64 actually tests EVP_DecodeBlock rejecting
        // invalid base64 lengths rather than the bound check itself.
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_cert = {0};
        rec_cert.name = (char*)"example.com"; rec_cert.type_code = 37; rec_cert.rdata_count = 4;
        rec_cert.rdata[0] = (char*)"PKIX"; rec_cert.rdata[1] = (char*)"12345"; rec_cert.rdata[2] = (char*)"8"; 
        rec_cert.rdata[3] = huge_b64;
        if (serialize_dns_record(packet, 2048, &offset, &rec_cert, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: CERT with huge base64 did not fail\n"); return 1;
        }

        // CERT: Valid Base64 that exceeds max_res_len (boundary check test)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_cert2 = {0};
        rec_cert2.name = (char*)"example.com"; rec_cert2.type_code = 37; rec_cert2.rdata_count = 4;
        rec_cert2.rdata[0] = (char*)"PKIX"; rec_cert2.rdata[1] = (char*)"12345"; rec_cert2.rdata[2] = (char*)"8";
        
        static char valid_long_b64[1101];
        for (int i = 0; i < 275; i++) memcpy(valid_long_b64 + i*4, "AAAA", 4);
        valid_long_b64[1100] = '\0';
        rec_cert2.rdata[3] = valid_long_b64;
        
        // max_res_len is intentionally small to trigger 'decoded_upper_bound > max_res_len'
        if (serialize_dns_record(packet, 50, &offset, &rec_cert2, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: CERT bound check (valid b64, small max_res_len) did not fail\n"); return 1;
        }

        // ZONEMD (Type 63) - huge hex string
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_zonemd = {0};
        rec_zonemd.name = (char*)"example.com"; rec_zonemd.type_code = 63; rec_zonemd.rdata_count = 4;
        rec_zonemd.rdata[0] = (char*)"2018031500"; rec_zonemd.rdata[1] = (char*)"1"; rec_zonemd.rdata[2] = (char*)"1";
        rec_zonemd.rdata[3] = huge_hex;
        if (serialize_dns_record(packet, 2048, &offset, &rec_zonemd, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: ZONEMD with huge hex did not fail\n"); return 1;
        }

        // NID (Type 104)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_nid = {0};
        rec_nid.name = (char*)"example.com"; rec_nid.type_code = 104; rec_nid.rdata_count = 2;
        rec_nid.rdata[0] = (char*)"10"; rec_nid.rdata[1] = (char*)"0000:0000:0000:0000";
        if (serialize_dns_record(packet, 20, &offset, &rec_nid, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: NID did not fail\n"); return 1;
        }

        // L32 (Type 105)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_l32 = {0};
        rec_l32.name = (char*)"example.com"; rec_l32.type_code = 105; rec_l32.rdata_count = 2;
        rec_l32.rdata[0] = (char*)"10"; rec_l32.rdata[1] = (char*)"192.0.2.1";
        if (serialize_dns_record(packet, 20, &offset, &rec_l32, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: L32 did not fail\n"); return 1;
        }

        // L64 (Type 106)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_l64 = {0};
        rec_l64.name = (char*)"example.com"; rec_l64.type_code = 106; rec_l64.rdata_count = 2;
        rec_l64.rdata[0] = (char*)"10"; rec_l64.rdata[1] = (char*)"0000:0000:0000:0000";
        if (serialize_dns_record(packet, 20, &offset, &rec_l64, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: L64 did not fail\n"); return 1;
        }

        // IPSECKEY (Type 45) - GW Type 1 (IPv4)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_ipseckey1 = {0};
        rec_ipseckey1.name = (char*)"example.com"; rec_ipseckey1.type_code = 45; rec_ipseckey1.rdata_count = 5;
        rec_ipseckey1.rdata[0] = (char*)"10"; rec_ipseckey1.rdata[1] = (char*)"1"; rec_ipseckey1.rdata[2] = (char*)"2";
        rec_ipseckey1.rdata[3] = (char*)"192.0.2.1"; rec_ipseckey1.rdata[4] = huge_b64;
        if (serialize_dns_record(packet, 20, &offset, &rec_ipseckey1, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: IPSECKEY gw1 did not fail\n"); return 1;
        }

        // IPSECKEY (Type 45) - GW Type 2 (IPv6)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_ipseckey2 = {0};
        rec_ipseckey2.name = (char*)"example.com"; rec_ipseckey2.type_code = 45; rec_ipseckey2.rdata_count = 5;
        rec_ipseckey2.rdata[0] = (char*)"10"; rec_ipseckey2.rdata[1] = (char*)"2"; rec_ipseckey2.rdata[2] = (char*)"2";
        rec_ipseckey2.rdata[3] = (char*)"2001:db8::1"; rec_ipseckey2.rdata[4] = huge_b64;
        if (serialize_dns_record(packet, 20, &offset, &rec_ipseckey2, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: IPSECKEY gw2 did not fail\n"); return 1;
        }

        // IPSECKEY (Type 45) - GW Type 3 (Domain Name)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_ipseckey3 = {0};
        rec_ipseckey3.name = (char*)"example.com"; rec_ipseckey3.type_code = 45; rec_ipseckey3.rdata_count = 5;
        rec_ipseckey3.rdata[0] = (char*)"10"; rec_ipseckey3.rdata[1] = (char*)"3"; rec_ipseckey3.rdata[2] = (char*)"2";
        rec_ipseckey3.rdata[3] = (char*)"gw.example.com"; rec_ipseckey3.rdata[4] = huge_b64;
        if (serialize_dns_record(packet, 20, &offset, &rec_ipseckey3, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: IPSECKEY gw3 did not fail\n"); return 1;
        }

        // AMTRELAY (Type 260) - Type 1 (IPv4)
        compress_ctx_init_packet(&ctx);
        offset = 0;
        dns_record_t rec_amtrelay1 = {0};
        rec_amtrelay1.name = (char*)"example.com"; rec_amtrelay1.type_code = 260; rec_amtrelay1.rdata_count = 4;
        rec_amtrelay1.rdata[0] = (char*)"10"; rec_amtrelay1.rdata[1] = (char*)"0"; rec_amtrelay1.rdata[2] = (char*)"1";
        rec_amtrelay1.rdata[3] = (char*)"192.0.2.1";
        if (serialize_dns_record(packet, 20, &offset, &rec_amtrelay1, &ctx, NULL, 0) != -1) {
            printf("Test 4 Failed: AMTRELAY type1 did not fail\n"); return 1;
        }

        printf("Test 4 Passed: All input bound overflow tests safely rejected\n");
    }

    printf("All tests passed safely.\n");
    return 0;
}
