#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../dns_wire.h"

char *read_entire_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (len < 0) { fclose(f); return NULL; }
  char *buf = malloc(len + 1);
  if (!buf) { fclose(f); return NULL; }
  fread(buf, 1, len, f);
  buf[len] = '\0';
  fclose(f);
  return buf;
}

char* extract_secret_from_config(const char* path) {
    char *cfg = read_entire_file(path);
    if (!cfg) return NULL;
    
    char *secret = NULL;
    char *p = strstr(cfg, "secret");
    if (p) {
        p += 6;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end) {
                *end = '\0';
                secret = strdup(p);
            }
        }
    }
    free(cfg);
    return secret;
}

int main(int argc, char **argv) {
    const char *conf_path = "/usr/local/etc/karictl.conf";
    int opt;
    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch (opt) {
            case 'f':
                conf_path = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-f config_path] <command> [args...]\n", argv[0]);
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-f config_path] <command> [args...]\n", argv[0]);
        fprintf(stderr, "Commands: status, reload [zone], reconfig, stop, notify <zone>, retransfer <zone>, zonestatus <zone>, tsig-keygen [keyname]\n");
        return 1;
    }

    if (strcmp(argv[optind], "tsig-keygen") == 0) {
        const char *keyname = "transfer-key";
        if (optind + 1 < argc) keyname = argv[optind + 1];
        
        unsigned char rand_bytes[32];
        if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
            fprintf(stderr, "Failed to generate random bytes\n");
            return 1;
        }
        
        char b64_key[64];
        EVP_EncodeBlock((unsigned char *)b64_key, rand_bytes, sizeof(rand_bytes));
        
        printf("key \"%s\" {\n", keyname);
        printf("  algorithm hmac-sha256;\n");
        printf("  secret \"%s\";\n", b64_key);
        printf("};\n");
        return 0;
    }

    char *secret_b64 = extract_secret_from_config(conf_path);
    if (!secret_b64) {
        fprintf(stderr, "Could not read secret from %s\n", conf_path);
        return 2;
    }

    uint8_t secret_decoded[256];
    int len = EVP_DecodeBlock(secret_decoded, (const unsigned char *)secret_b64, strlen(secret_b64));
    if (len < 0) {
        fprintf(stderr, "Failed to decode base64 secret\n");
        return 2;
    }
    int padding = 0;
    size_t slen = strlen(secret_b64);
    if (slen > 0 && secret_b64[slen - 1] == '=') padding++;
    if (slen > 1 && secret_b64[slen - 2] == '=') padding++;
    size_t secret_decoded_len = len - padding;
    free(secret_b64);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, "/var/run/karidns/control.sock", sizeof(un.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&un, sizeof(un)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    char buf[1024];
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0) {
        fprintf(stderr, "Failed to receive challenge\n");
        close(sock);
        return 1;
    }
    buf[r] = '\0';

    if (strncmp(buf, "CHALLENGE ", 10) != 0) {
        fprintf(stderr, "Invalid challenge format\n");
        close(sock);
        return 2;
    }

    char *challenge = buf + 10;
    char *nl = strchr(challenge, '\n');
    if (nl) *nl = '\0';

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    HMAC(EVP_sha256(), secret_decoded, secret_decoded_len, 
         (unsigned char*)challenge, 64, md, &md_len);
    
    char auth_msg[256];
    char expected[65];
    for(unsigned int k=0; k<md_len; k++) snprintf(&expected[k*2], 3, "%02x", md[k]);
    expected[64] = '\0';
    
    int mlen = snprintf(auth_msg, sizeof(auth_msg), "AUTH %s\n", expected);
    send(sock, auth_msg, mlen, 0);

    r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0) {
        fprintf(stderr, "Failed to receive auth response\n");
        close(sock);
        return 2;
    }
    buf[r] = '\0';

    if (strncmp(buf, "OK", 2) != 0) {
        fprintf(stderr, "Authentication failed: %s", buf);
        close(sock);
        return 2;
    }

    char cmd_msg[512];
    if (optind + 1 < argc) {
        snprintf(cmd_msg, sizeof(cmd_msg), "%s %s\n", argv[optind], argv[optind + 1]);
    } else {
        snprintf(cmd_msg, sizeof(cmd_msg), "%s\n", argv[optind]);
    }

    send(sock, cmd_msg, strlen(cmd_msg), 0);

    if (strcmp(argv[optind], "status") == 0) {
        size_t expected_len = 3 + sizeof(karidns_status_t);
        size_t total = 0;
        while (total < expected_len) {
            r = recv(sock, buf + total, sizeof(buf) - total, 0);
            if (r <= 0) break;
            total += r;
        }
        if (total >= expected_len && strncmp(buf, "OK ", 3) == 0) {
            karidns_status_t st;
            memcpy(&st, buf + 3, sizeof(st));
            
            struct utsname un;
            uname(&un);
            
            int num_cpus = 1;
            int mib[2] = { CTL_HW, HW_NCPU };
            size_t clen = sizeof(num_cpus);
            sysctl(mib, 2, &num_cpus, &clen, NULL, 0);
            
            char boot_str[64], config_str[64];
            struct tm *tm_info;
            tm_info = localtime(&st.boot_time);
            strftime(boot_str, sizeof(boot_str), "%d-%b-%Y %H:%M:%S.%03d", tm_info);
            
            tm_info = localtime(&st.last_configured_time);
            strftime(config_str, sizeof(config_str), "%d-%b-%Y %H:%M:%S.%03d", tm_info);
            
            printf("version: KariDNS 1.0.0 (Authoritative)\n");
            printf("running on %s: %s %s %s\n", un.nodename, un.sysname, un.machine, un.release);
            printf("boot time: %s\n", boot_str);
            printf("last configured: %s\n", config_str);
            printf("configuration file: %s\n", st.config_file[0] ? st.config_file : "(unknown)");
            printf("CPUs found: %d\n", num_cpus);
            printf("worker threads: %d\n", st.worker_threads);
            printf("number of zones: %d (0 automatic)\n", st.num_zones);
            printf("debug level: 0\n");
            printf("xfers running: %d\n", st.xfers_running);
            printf("xfers deferred: %d\n", st.xfers_deferred);
            printf("xfers first refresh: %d\n", st.xfers_first_refresh);
            printf("soa queries in progress: %d\n", st.soa_queries_in_progress);
            printf("query logging is %s\n", st.query_logging ? "ON" : "OFF");
            printf("response logging is %s\n", st.response_logging ? "ON" : "OFF");
            printf("tcp clients: %d/%d (High-water: %d)\n", st.tcp_clients, st.max_tcp_clients, st.tcp_high_water);
            printf("server is up and running%s\n", st.frontend_alive ? "" : " (Frontend is down)");
            
            printf("\n--- Security & Rate Limit Stats ---\n");
            printf("RRL dropped: %lu\n", st.rrl_dropped);
            printf("RRL slipped: %lu\n", st.rrl_slipped);
            printf("EDE Prohibited (18): %lu\n", st.ede_proh);
            printf("EDE NotAuthoritative (20): %lu\n", st.ede_na);
            printf("EDE NotSupported (21): %lu\n", st.ede_ns);
            printf("EDE Other: %lu\n", st.ede_oth);
            printf("-----------------------------------\n");
        } else {
            buf[total] = '\0';
            printf("%s", buf);
        }
    } else {
        r = recv(sock, buf, sizeof(buf) - 1, 0);
        if (r > 0) {
            buf[r] = '\0';
            printf("%s", buf);
            if (strncmp(buf, "ERROR", 5) == 0) {
                close(sock);
                return 3;
            }
        }
    }

    close(sock);
    return 0;
}
