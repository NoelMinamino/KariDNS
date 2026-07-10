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
        offset = 0;
        dns_record_t rec_tlsa = {0};
        rec_tlsa.name = (char*)"_443._tcp.example.com"; rec_tlsa.type_code = 52; rec_tlsa.rdata_count = 4;
        rec_tlsa.rdata[0] = (char*)"3"; rec_tlsa.rdata[1] = (char*)"1"; rec_tlsa.rdata[2] = (char*)"1"; rec_tlsa.rdata[3] = (char*)"abcdef";
        if (serialize_dns_record(packet, 20, &offset, &rec_tlsa, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: TLSA did not fail\n"); return 1;
        }

        // CERT
        offset = 0;
        dns_record_t rec_cert = {0};
        rec_cert.name = (char*)"example.com"; rec_cert.type_code = 37; rec_cert.rdata_count = 4;
        rec_cert.rdata[0] = (char*)"PKIX"; rec_cert.rdata[1] = (char*)"12345"; rec_cert.rdata[2] = (char*)"8"; 
        rec_cert.rdata[3] = (char*)"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        if (serialize_dns_record(packet, 20, &offset, &rec_cert, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: CERT did not fail\n"); return 1;
        }

        // NAPTR
        offset = 0;
        dns_record_t rec_naptr = {0};
        rec_naptr.name = (char*)"example.com"; rec_naptr.type_code = 35; rec_naptr.rdata_count = 6;
        rec_naptr.rdata[0] = (char*)"100"; rec_naptr.rdata[1] = (char*)"10"; rec_naptr.rdata[2] = (char*)"S";
        rec_naptr.rdata[3] = (char*)"SIP+D2U"; rec_naptr.rdata[4] = (char*)""; rec_naptr.rdata[5] = (char*)"_sip._udp.example.com.";
        if (serialize_dns_record(packet, 20, &offset, &rec_naptr, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: NAPTR did not fail\n"); return 1;
        }

        // NSEC3PARAM
        offset = 0;
        dns_record_t rec_nsec3param = {0};
        rec_nsec3param.name = (char*)"example.com"; rec_nsec3param.type_code = 51; rec_nsec3param.rdata_count = 4;
        rec_nsec3param.rdata[0] = (char*)"1"; rec_nsec3param.rdata[1] = (char*)"0"; rec_nsec3param.rdata[2] = (char*)"10";
        rec_nsec3param.rdata[3] = (char*)"12345678";
        if (serialize_dns_record(packet, 20, &offset, &rec_nsec3param, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: NSEC3PARAM did not fail\n"); return 1;
        }

  
        // HINFO
        offset = 0;
        dns_record_t rec_hinfo = {0};
        rec_hinfo.name = (char*)"example.com"; rec_hinfo.type_code = 13; rec_hinfo.rdata_count = 2;
        rec_hinfo.rdata[0] = (char*)"INTEL-386"; rec_hinfo.rdata[1] = (char*)"UNIX";
        if (serialize_dns_record(packet, 20, &offset, &rec_hinfo, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: HINFO did not fail\n"); return 1;
        }

        // URI
        offset = 0;
        dns_record_t rec_uri = {0};
        rec_uri.name = (char*)"example.com"; rec_uri.type_code = 256; rec_uri.rdata_count = 3;
        rec_uri.rdata[0] = (char*)"10"; rec_uri.rdata[1] = (char*)"1"; rec_uri.rdata[2] = (char*)"ftp://ftp.example.com/public";
        if (serialize_dns_record(packet, 20, &offset, &rec_uri, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: URI did not fail\n"); return 1;
        }

        // OPENPGPKEY
        offset = 0;
        dns_record_t rec_openpgpkey = {0};
        rec_openpgpkey.name = (char*)"example.com"; rec_openpgpkey.type_code = 61; rec_openpgpkey.rdata_count = 1;
        rec_openpgpkey.rdata[0] = (char*)"mQENBFxJ0V4BCAD..."; // Dummy long string for overflow test
        if (serialize_dns_record(packet, 20, &offset, &rec_openpgpkey, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: OPENPGPKEY did not fail\n"); return 1;
        }

        // DHCID
        offset = 0;
        dns_record_t rec_dhcid = {0};
        rec_dhcid.name = (char*)"example.com"; rec_dhcid.type_code = 49; rec_dhcid.rdata_count = 1;
        rec_dhcid.rdata[0] = (char*)"AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=";
        if (serialize_dns_record(packet, 20, &offset, &rec_dhcid, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: DHCID did not fail\n"); return 1;
        }

        // EUI48
        offset = 0;
        dns_record_t rec_eui48 = {0};
        rec_eui48.name = (char*)"example.com"; rec_eui48.type_code = 108; rec_eui48.rdata_count = 1;
        rec_eui48.rdata[0] = (char*)"00-11-22-33-44-55";
        if (serialize_dns_record(packet, 17, &offset, &rec_eui48, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: EUI48 did not fail\n"); return 1;
        }

        // EUI64
        offset = 0;
        dns_record_t rec_eui64 = {0};
        rec_eui64.name = (char*)"example.com"; rec_eui64.type_code = 109; rec_eui64.rdata_count = 1;
        rec_eui64.rdata[0] = (char*)"00-11-22-33-44-55-66-77";
        if (serialize_dns_record(packet, 20, &offset, &rec_eui64, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: EUI64 did not fail\n"); return 1;
        }

        // ZONEMD
        offset = 0;
        dns_record_t rec_zonemd = {0};
        rec_zonemd.name = (char*)"example.com"; rec_zonemd.type_code = 63; rec_zonemd.rdata_count = 4;
        rec_zonemd.rdata[0] = (char*)"2018031500"; rec_zonemd.rdata[1] = (char*)"1"; rec_zonemd.rdata[2] = (char*)"1";
        rec_zonemd.rdata[3] = (char*)"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
        if (serialize_dns_record(packet, 20, &offset, &rec_zonemd, &ctx, NULL, 0) != -1) {
            printf("Test 3 Failed: ZONEMD did not fail\n"); return 1;
        }
      printf("Test 3 Passed: All new records safely rejected small max_res_len\n");
    }

    printf("All tests passed safely.\n");
    return 0;
}
