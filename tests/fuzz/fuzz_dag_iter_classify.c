#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Override syslog to prevent massive disk I/O and CPU usage during fuzzing
void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

// +trace2 (tools/dag_iter.c) parses every response it receives from an
// arbitrary nameserver on the Internet with dag_iter_classify(): CNAME/DNAME
// chain walking, referral / glue extraction with bailiwick checks, SOA
// detection. This harness feeds it untrusted packets, using the packet's own
// question as the expected one (so the deeper paths are reached) and a
// fuzzer-chosen suffix of that name as the zone being queried.
// Mode byte bit 0 = 1 instead feeds the input to the named.root parser
// used by +roothints=FILE.
#define main dag_main
#include "../../tools/dag.c"
#undef main

#include "../../tools/dag_iter.h"
#include "../../tools/dag_roothints.h"

static void fuzz_classify(uint8_t mode, const uint8_t *pkt, size_t len) {
    char qname[256] = "www.example.test.";
    uint16_t qtype = 1;
    if (len >= 12) {
        size_t off = 12;
        char *name = NULL;
        if (expand_wire_name(pkt, len, off, &off, &g_dag_arena, &name) == 0 && name && off + 2 <= len) {
            snprintf(qname, sizeof(qname), "%s", name);
            qtype = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
        }
    }
    int labels = dag_iter_label_count(qname);
    char zone[256];
    dag_iter_name_suffix(qname, labels > 0 ? (mode >> 1) % (labels + 1) : 0, zone, sizeof(zone));

    it_resp_t *r = malloc(sizeof(*r));
    if (!r) return;
    (void)dag_iter_classify(pkt, len, qname, qtype, zone, r);
    /* 分類結果の文字列が必ず NUL 終端されていること */
    if (strnlen(r->target, sizeof(r->target)) == sizeof(r->target) ||
        strnlen(r->cut, sizeof(r->cut)) == sizeof(r->cut) ||
        r->nns > IT_MAX_NS || r->nglue > IT_MAX_GLUE || r->naddr > IT_MAX_ADDRS) {
        abort();
    }
    (void)dag_iter_kind_name(r->kind);
    free(r);
    reset_dag_arena();
}

static void fuzz_roothints(const uint8_t *data, size_t size) {
    char *text = malloc(size + 1);
    roothints_t *rh = malloc(sizeof(*rh));
    if (text && rh) {
        memcpy(text, data, size);
        text[size] = '\0';
        char err[256];
        int rc = roothints_parse_text(text, rh, err, sizeof(err));
        if (rc > ROOTHINT_MAX || (rc > 0 && rc != rh->count)) abort();
    }
    free(text);
    free(rh);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t mode = data[0];
    if (mode & 1) {
        fuzz_roothints(data + 1, size - 1);
    } else {
        fuzz_classify(mode, data + 1, size - 1);
    }
    return 0;
}
