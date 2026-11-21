/* libFuzzer harness: what an agent and a controller of dnsqps read from the control connection (tools/dnsqps_agent.c): the message parser, the numbers, the
 * result of an agent with its histogram, the options a controller sends, and the source prefix.  Every input is untrusted; the checks are the sanitizers. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../tools/dnsqps.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > DQ_MSG_MAX) return 0;
    char err[200];
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    dq_msg_t m;
    if (dq_msg_parse(buf, size, &m, err, sizeof err) == 0) {
        dq_report_t r;
        uint64_t u;
        dq_result_get(&m, &r, err, sizeof err);
        dq_msg_u64(&m, "sent", &u);
        dq_msg_get(&m, "arg");
        char *toks[DQ_MAXTOK];
        int n = 0;
        for (unsigned i = 0; i < m.n && n < DQ_MAXTOK; i++)
            if (!strcmp(m.k[i], "arg")) toks[n++] = m.v[i];
        if (dq_agent_check_tokens(toks, n, err, sizeof err) == 0) {
            dq_cfg_t c;
            dq_cfg_default(&c);
            if (dq_parse_args(&c, n, toks, err, sizeof err) == 0) dq_cfg_check(&c, err, sizeof err);
        }
    }
    free(buf);
    /* the same bytes as text: a histogram, a prefix, a host:port */
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';
    dq_hist_t h;
    dq_hist_init(&h);
    dq_hist_decode(&h, s);
    dq_srcpfx_t p, q;
    if (dq_parse_prefix(s, &p)) {
        uint64_t rng = 1 + size;
        uint8_t a[16];
        dq_prefix_pick(&p, &rng, a);
        dq_prefix_reserved(&p);
        for (unsigned k = 1; k < 20; k += 7) dq_prefix_slice(&p, k, k - 1, &q);
        dq_prefix_format(&p, err, sizeof err);
    }
    char host[64];
    int port;
    dq_hostport_strict(s, host, sizeof host, &port);
    free(s);
    return 0;
}
