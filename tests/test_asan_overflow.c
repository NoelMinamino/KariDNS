#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../dns_wire.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
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
    

    // Test 4: allow-transfer key correctly sets zone->tsig_key
    memset(&cfg, 0, sizeof(cfg));
    char conf_acl[1024];
    strcpy(conf_acl, "zone \"example.com\" { type master; file \"dummy\"; allow-transfer { key \"mykey\"; }; };");
    char* copy_acl = strdup(conf_acl);
    int res_acl = parse_named_conf(copy_acl, &cfg);
    free(copy_acl);
    if (res_acl == 0 && cfg.zones && cfg.zones->tsig_key && strcmp(cfg.zones->tsig_key, "mykey") == 0 && cfg.zones->allow_transfer_count == 0) {
        printf("Test 4 Passed: allow-transfer key correctly parsed as tsig_key\n");
    } else {
        printf("Test 4 Failed: allow-transfer key parsing failed! res_acl=%d, tsig_key=%s, count=%d\n",
               res_acl, cfg.zones ? (cfg.zones->tsig_key ? cfg.zones->tsig_key : "NULL") : "NO ZONE",
               cfg.zones ? cfg.zones->allow_transfer_count : -1);
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
        // X25 (Type 19)
        dns_record_t rec_x25 = {0};
        rec_x25.name = (char*)"example.com"; rec_x25.type_code = 19; rec_x25.rdata_count = 1;
        rec_x25.rdata[0] = (char*)"311061700956";
        if (assert_bound_checked(&rec_x25)) return 1;

        // ISDN (Type 20)
        dns_record_t rec_isdn = {0};
        rec_isdn.name = (char*)"example.com"; rec_isdn.type_code = 20; rec_isdn.rdata_count = 2;
        rec_isdn.rdata[0] = (char*)"150862028003217"; rec_isdn.rdata[1] = (char*)"004";
        if (assert_bound_checked(&rec_isdn)) return 1;

        // NSAP (Type 22)
        // ゾーンパーサーで0xとドットが除去された後の正規化されたHex文字列を想定
        dns_record_t rec_nsap = {0};
        rec_nsap.name = (char*)"example.com"; rec_nsap.type_code = 22; rec_nsap.rdata_count = 1;
        rec_nsap.rdata[0] = (char*)"47000580005a0000000001e133ffffff00016100";
        if (assert_bound_checked(&rec_nsap)) return 1;

        // GPOS (Type 27)
        dns_record_t rec_gpos = {0};
        rec_gpos.name = (char*)"example.com"; rec_gpos.type_code = 27; rec_gpos.rdata_count = 3;
        rec_gpos.rdata[0] = (char*)"-32.6866"; rec_gpos.rdata[1] = (char*)"-70.1509"; rec_gpos.rdata[2] = (char*)"12.0";
        if (assert_bound_checked(&rec_gpos)) return 1;

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

        // LOC (Type 29)
        dns_record_t rec_loc = {0};
        rec_loc.name = (char*)"example.com"; rec_loc.type_code = 29; rec_loc.rdata_count = 10;
        rec_loc.rdata[0] = (char*)"37"; rec_loc.rdata[1] = (char*)"26"; rec_loc.rdata[2] = (char*)"0.000"; rec_loc.rdata[3] = (char*)"N";
        rec_loc.rdata[4] = (char*)"122"; rec_loc.rdata[5] = (char*)"8"; rec_loc.rdata[6] = (char*)"0.000"; rec_loc.rdata[7] = (char*)"W";
        rec_loc.rdata[8] = (char*)"100.00m"; rec_loc.rdata[9] = (char*)"1m";
        if (assert_bound_checked(&rec_loc)) return 1;

        // APL (Type 42)
        dns_record_t rec_apl = {0};
        rec_apl.name = (char*)"example.com"; rec_apl.type_code = 42; rec_apl.rdata_count = 2;
        rec_apl.rdata[0] = (char*)"1:192.168.0.0/24";
        rec_apl.rdata[1] = (char*)"!2:2001:db8::/32";
        if (assert_bound_checked(&rec_apl)) return 1;

        printf("Test 4 Passed: All input bound overflow tests safely rejected\n");
    }

    // Test 5: $GENERATE directive tests
    {
        printf("\n--- Test 5: $GENERATE directive ---\n");
        
        #define RUN_GEN_TEST(input, expect_fail) do { \
            zone_arena_t arena = {0}; \
            parse_context_t ctx = {0}; \
            parse_error_t err = {0}; \
            ctx.err_out = &err; \
            char *buf = strdup(input); \
            int res = parse_zone_fast(buf, strlen(buf), &arena, &ctx); \
            if (expect_fail) { \
                if (res != -1) { printf("FAIL: Expected error for '%s'\n", input); return 1; } \
                else { printf("PASS: Expected error for '%s' -> %s\n", input, err.error_message); } \
            } else { \
                if (res == -1) { printf("FAIL: Expected success for '%s', got error: %s\n", input, err.error_message); return 1; } \
                else { printf("PASS: Success for '%s'\n", input); } \
            } \
            zone_arena_destroy(&arena); \
            free(buf); \
        } while(0)

        // 正常系: 1-5 
        RUN_GEN_TEST("$GENERATE 1-5 host-$ A 10.0.0.$", false);
        // 異常系: stop < start
        RUN_GEN_TEST("$GENERATE 10-1 host-$ A 10.0.0.$", true);
        // 異常系: step 0
        RUN_GEN_TEST("$GENERATE 1-10/0 host-$ A 10.0.0.$", true);
        // 異常系: MAX_GENERATE_COUNT 超え
        RUN_GEN_TEST("$GENERATE 1-999999 host-$ A 10.0.0.$", true);
        // 異常系: width異常
        RUN_GEN_TEST("$GENERATE 1-10 host-${0,999,d} A 10.0.0.$", true);
        // 異常系: base異常
        RUN_GEN_TEST("$GENERATE 1-10 host-${0,3,q} A 10.0.0.$", true);
        // 正常系: $$
        RUN_GEN_TEST("$GENERATE 1-5 host-$$ A 10.0.0.$", false);
        // 正常系: 負のoffset
        RUN_GEN_TEST("$GENERATE 1-5 host-${-5,3,d} A 10.0.0.$", false);
    }

    // Test 6: LOC and APL Validation Tests
    {
        printf("\n--- Test 6: LOC and APL Specific Validation ---\n");
        uint8_t res_buf[512];
        uint16_t offset = 0;
        compress_ctx_t comp_ctx = {0};

        // LOC: Invalid latitude (> 90 degrees = 324000 sec)
        dns_record_t rec_loc_badlat = {0};
        rec_loc_badlat.name = (char*)"example.com"; rec_loc_badlat.type_code = 29; rec_loc_badlat.rdata_count = 10;
        rec_loc_badlat.rdata[0] = (char*)"91"; rec_loc_badlat.rdata[1] = (char*)"0"; rec_loc_badlat.rdata[2] = (char*)"0"; rec_loc_badlat.rdata[3] = (char*)"N";
        rec_loc_badlat.rdata[4] = (char*)"0"; rec_loc_badlat.rdata[5] = (char*)"0"; rec_loc_badlat.rdata[6] = (char*)"0"; rec_loc_badlat.rdata[7] = (char*)"E";
        rec_loc_badlat.rdata[8] = (char*)"0m"; rec_loc_badlat.rdata[9] = (char*)"0m";
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_loc_badlat, &comp_ctx, NULL, 0) != -1) {
            printf("FAIL: Expected failure for invalid latitude 91 N\n"); return 1;
        }

        // LOC: Invalid direction ('X')
        dns_record_t rec_loc_baddir = {0};
        rec_loc_baddir.name = (char*)"example.com"; rec_loc_baddir.type_code = 29; rec_loc_baddir.rdata_count = 10;
        rec_loc_baddir.rdata[0] = (char*)"10"; rec_loc_baddir.rdata[1] = (char*)"0"; rec_loc_baddir.rdata[2] = (char*)"0"; rec_loc_baddir.rdata[3] = (char*)"X";
        rec_loc_baddir.rdata[4] = (char*)"0"; rec_loc_baddir.rdata[5] = (char*)"0"; rec_loc_baddir.rdata[6] = (char*)"0"; rec_loc_baddir.rdata[7] = (char*)"E";
        rec_loc_baddir.rdata[8] = (char*)"0m"; rec_loc_baddir.rdata[9] = (char*)"0m";
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_loc_baddir, &comp_ctx, NULL, 0) != -1) {
            printf("FAIL: Expected failure for invalid direction 'X'\n"); return 1;
        }
        
        // LOC: Valid short form
        dns_record_t rec_loc_short = {0};
        rec_loc_short.name = (char*)"example.com"; rec_loc_short.type_code = 29; rec_loc_short.rdata_count = 5;
        rec_loc_short.rdata[0] = (char*)"37"; rec_loc_short.rdata[1] = (char*)"N";
        rec_loc_short.rdata[2] = (char*)"122"; rec_loc_short.rdata[3] = (char*)"W";
        rec_loc_short.rdata[4] = (char*)"0m";
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_loc_short, &comp_ctx, NULL, 0) == -1) {
            printf("FAIL: Expected success for LOC short form\n"); return 1;
        }

        // APL: Invalid AFI (3)
        dns_record_t rec_apl_badafi = {0};
        rec_apl_badafi.name = (char*)"example.com"; rec_apl_badafi.type_code = 42; rec_apl_badafi.rdata_count = 1;
        rec_apl_badafi.rdata[0] = (char*)"3:192.168.0.0/24";
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_apl_badafi, &comp_ctx, NULL, 0) != -1) {
            printf("FAIL: Expected failure for APL invalid AFI\n"); return 1;
        }
        
        // APL: Invalid IPv4 Prefix (33)
        dns_record_t rec_apl_badpfx = {0};
        rec_apl_badpfx.name = (char*)"example.com"; rec_apl_badpfx.type_code = 42; rec_apl_badpfx.rdata_count = 1;
        rec_apl_badpfx.rdata[0] = (char*)"1:192.168.0.0/33";
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_apl_badpfx, &comp_ctx, NULL, 0) != -1) {
            printf("FAIL: Expected failure for APL invalid IPv4 Prefix\n"); return 1;
        }

        // APL: Zero rdata (valid, 0 length)
        dns_record_t rec_apl_zero = {0};
        rec_apl_zero.name = (char*)"example.com"; rec_apl_zero.type_code = 42; rec_apl_zero.rdata_count = 0;
        offset = 0;
        if (serialize_dns_record(res_buf, sizeof(res_buf), &offset, &rec_apl_zero, &comp_ctx, NULL, 0) == -1) {
            printf("FAIL: Expected success for APL 0 rdata\n"); return 1;
        }

        printf("PASS: LOC and APL validations\n");
    }

    // Test: dns_zone_parser.c edge cases
    {
        zone_arena_t arena;
        zone_arena_init(&arena);
        parse_error_t err = {0};
        parse_context_t ctx = {
            .base_dir = ".",
            .default_origin = "example.com.",
            .is_standalone_mode = true,
            .err_out = &err,
        };

        // 1. Normal quotes
        char buf1[] = "example.com. 3600 IN TXT \"hello world\"\n";
        int r1 = parse_zone_fast(buf1, strlen(buf1), &arena, &ctx);
        if (r1 < 0) {
            printf("FAIL: Test 1 (Normal quotes) failed. err=%s\n", err.error_message);
            return 1;
        }

        // 2. Unterminated quote
        char buf2[] = "example.com. 3600 IN TXT ( \"hello\nworld\" )\n";
        int r2 = parse_zone_fast(buf2, strlen(buf2), &arena, &ctx);
        if (r2 == 0) {
            printf("FAIL: Test 2 (Unterminated quote) incorrectly succeeded.\n");
            return 1;
        }
        if (!err.error_message || !strstr(err.error_message, "Unterminated quoted string")) {
            printf("FAIL: Test 2 (Unterminated quote) bad error message: %s\n", err.error_message ? err.error_message : "NULL");
            return 1;
        }

        // 3. Exceeds MAX_FIELDS
        char buf3[4096];
        strcpy(buf3, "example.com. 3600 IN TXT ( ");
        for (int i = 0; i < 120; i++) {
            strcat(buf3, "\"field\" ");
        }
        strcat(buf3, ")\n");
        int r3 = parse_zone_fast(buf3, strlen(buf3), &arena, &ctx);
        if (r3 == 0) {
            printf("FAIL: Test 3 (MAX_FIELDS exceeded) incorrectly succeeded.\n");
            return 1;
        }
        if (!err.error_message || !strstr(err.error_message, "Too many fields")) {
            printf("FAIL: Test 3 (MAX_FIELDS exceeded) bad error message: %s\n", err.error_message ? err.error_message : "NULL");
            return 1;
        }

        printf("PASS: dns_zone_parser tests\n");
        zone_arena_destroy(&arena);
    }

    printf("All tests passed safely.\n");
    return 0;
}
