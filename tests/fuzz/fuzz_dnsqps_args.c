/* libFuzzer harness: what dnsqps reads from the user's files and command line: the rc file (~/.dnsqpsrc), the arguments with the dig-style +options,
 * the query file lines with their per-line options, a name, the type mix and a host:port. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../tools/dnsqps.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 8192) return 0;
    char err[300];
    dq_cfg_t c;
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    dq_cfg_default(&c);
    dq_parse_rc_buf(&c, s, size, err, sizeof err);

    /* the same bytes as arguments: split at NUL, newline and space */
    char *argv[64];
    int argc = 0;
    char *p = s;
    while (*p && argc < 64) {
        while (*p == ' ' || *p == '\n') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        if (*p) *p++ = '\0';
    }
    dq_cfg_default(&c);
    if (dq_parse_args(&c, argc, argv, err, sizeof err) == 0) dq_cfg_check(&c, err, sizeof err);

    dq_cfg_default(&c);
    dq_qtab_t t;
    char *copy = malloc(size + 1);
    if (copy) {
        memcpy(copy, data, size);
        copy[size] = '\0';
        if (dq_qtab_from_lines(&t, &c, copy, size, err, sizeof err) == 0) {
            uint8_t q[DQ_MAXQ];
            dq_cur_t cur;
            dq_cur_init(&cur, &t, 0, 1, 1);
            for (int i = 0; i < 8; i++) dq_next_query(&t, &cur, q, sizeof q, 1);
            /* the pre-built frames of the same table, and the picks that index them */
            static const uint8_t mac[6] = { 2, 0, 0, 0, 0, 1 }, ip[4] = { 198, 18, 0, 1 };
            dq_frame_tpl_t tpl;
            dq_pf_t pf;
            dq_frame_tpl_init(&tpl, mac, mac, false, ip, ip, 40000, 53);
            if (dq_pf_build(&pf, &t, &tpl, err, sizeof err) == 0) {
                dq_cur_init(&cur, &t, 0, 1, 1);
                for (int i = 0; i < 8; i++) {
                    dq_pick_t pk;
                    uint16_t fl, co;
                    if (dq_next_pick(&t, &cur, &pk, 1)) dq_pf_get(&pf, dq_pf_index(&t, &pk), &fl, &co);
                }
                dq_pf_free(&pf);
            }
            dq_qtab_free(&t);
        }
        free(copy);
    }
    uint8_t w[256];
    dq_name_to_wire(s, w, sizeof w);
    uint16_t ty[DQ_MAXTYPES];
    uint32_t wt[DQ_MAXTYPES];
    dq_parse_qtypes(s, ty, wt, err, sizeof err);
    char host[64];
    int port;
    dq_split_hostport(s, host, sizeof host, &port);
    free(s);
    return 0;
}
