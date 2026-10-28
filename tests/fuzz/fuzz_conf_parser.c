#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../dns_config_parser.h"
#include "../../dns_tsig_acl.h"

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// Stub for open_via_dir_cache which is used in dns_config_parser.c but defined in dns_server_core.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)path; (void)flags; (void)mode; (void)writable;
    return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *text_buf = malloc(size + 1);
    if (!text_buf) return 0;
    memcpy(text_buf, data, size);
    text_buf[size] = '\0';

    server_config_t config;
    memset(&config, 0, sizeof(config));

    /* options { directory }: the directory of a running server (a reload) is pinned, one that was not started with a directory is a pin
     * to "none"; the bytes choose, so that the prefixing of relative paths, the changed-directory report and the unpinned scan all run */
    if (size & 2) config_pin_directory((size & 4) ? "/pinned" : NULL);
    else config_unpin_directory();
    int prc = parse_named_conf(text_buf, &config);
    config_unpin_directory();

    /* B8t-2: the settings a primary sends for each zone (zone_settings_render) must be accepted by the restricted parser on the secondary,
     * and merging them into a zone block (zone_config_with_received) must not fail or leak */
    char err[200];
    if (prc == 0) {
        /* BIND address match lists: every ACL decision the server makes for a zone, with and without a key, on both address families */
        static const char *const ips[] = { "192.0.2.1", "10.0.0.1", "127.0.0.1", "2001:db8::1", "::1", "not an address" };
        struct sockaddr_in loc4;
        memset(&loc4, 0, sizeof(loc4));
        loc4.sin_family = AF_INET;
        loc4.sin_addr.s_addr = htonl(0xC0000201u);
        for (view_config_t *v = config.views; v; v = v->next) {
            for (zone_config_t *z = v->zones; z; z = z->next) {
                for (size_t i = 0; i < sizeof(ips) / sizeof(ips[0]); i++) {
                    const char *key = config.keys ? config.keys->name : NULL;
                    (void)query_acl_permits(&config, z, v->name, ips[i], key, &loc4);
                    (void)query_acl_permits(&config, z, v->name, ips[i], NULL, NULL);
                    (void)zone_transfer_acl_allows_in_view(&config, z, v->name, ips[i], key);
                    (void)zone_update_acl_allows_in_view(&config, z, v->name, ips[i], key);
                    (void)zone_notify_acl_allows(&config, z, v->name, ips[i], key);
                }
            }
        }
        char *out = malloc(KARIDNS_SETTINGS_MAX + 1);
        for (view_config_t *v = config.views; out && v; v = v->next) {
            for (zone_config_t *z = v->zones; z; z = z->next) {
                size_t n = zone_settings_render(&config, z, false, out, KARIDNS_SETTINGS_MAX + 1);
                if (n == 0 || n == (size_t)-1) continue;
                zone_ext_shared_t *rx = db_settings_parse(out, n, err, sizeof(err));
                if (!rx) __builtin_trap();                     /* what a primary sends, a secondary must be able to read */
                char note[160];
                zone_config_t *m = zone_config_with_received(z->domain, z, &rx->ext, &config, note, sizeof(note));
                free_zone_config(m);
                zone_ext_shared_unref(rx);
            }
        }
        free(out);
    }

    free_server_config_fields(&config);

    /* B7a: the same bytes as the settings text of a database zone (restricted parse, no include, a whitelist of statements) */
    zone_ext_shared_t *sh = db_settings_parse(text_buf, size, err, sizeof(err));
    if (!sh && err[0] == '\0') __builtin_trap();     /* a refusal says why */
    zone_ext_shared_unref(sh);
    free(text_buf);
    return 0;
}
