#include "dag_trace_common.h"

void trace_record_result(const char *server, ssize_t n, const uint8_t *resp, long elapsed_ms, const char *proto) {
    if (n < 12) return;
    server_result_t *sres = alloc_result_row();
    if (!sres) return;
    sres->rcode = resp[3] & 0x0F;
    sres->qdcount = (resp[4] << 8) | resp[5];
    sres->ancount = (resp[6] << 8) | resp[7];
    sres->nscount = (resp[8] << 8) | resp[9];
    sres->arcount = (resp[10] << 8) | resp[11];
    sres->qr = resp[2] & 0x80; sres->aa = resp[2] & 0x04; sres->tc = resp[2] & 0x02; sres->rd = resp[2] & 0x01;
    sres->ra = resp[3] & 0x80; sres->ad = resp[3] & 0x20; sres->cd = resp[3] & 0x10;
    sres->msg_index = 1;
    sres->msg_total = 1;
    size_t to_copy = (size_t)n < sizeof(sres->resp_buf) ? (size_t)n : sizeof(sres->resp_buf);
    memcpy(sres->resp_buf, resp, to_copy);
    sres->resp_len = (ssize_t)to_copy;
    calculate_packet_hashes(resp, n, &sres->semantic_hash, &sres->record_hash);
    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", server);
    snprintf(sres->proto, sizeof(sres->proto), "%s", proto ? proto : "UDP");
    sres->elapsed_ms = elapsed_ms;
    g_server_count++;
}

void trace_collect_rrs_by_type(const uint8_t *pkt, size_t pkt_len, size_t *roff,
                               int section_count, uint16_t want_type,
                               char out[][256], char owners[][256], int *out_count, int out_cap) {
    for (int i = 0; i < section_count; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(pkt, pkt_len, roff, &g_dag_arena, &rec, &type) != 0) break;
        if (type == want_type && *out_count < out_cap && rec.rdata_count > 0) {
            if (owners) snprintf(owners[*out_count], 256, "%s", rec.name);
            snprintf(out[(*out_count)++], 256, "%s", rec.rdata[0]);
        }
    }
}

bool trace_name_is_subdomain(const char *name, const char *owner) {
    size_t nl = strlen(name), ol = strlen(owner);
    while (nl > 0 && name[nl - 1] == '.') nl--;
    while (ol > 0 && owner[ol - 1] == '.') ol--;
    if (ol == 0) return true; /* root */
    if (nl < ol) return false;
    if (strncasecmp(name + nl - ol, owner, ol) != 0) return false;
    return nl == ol || name[nl - ol - 1] == '.';
}

bool trace_name_equal(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    while (al > 0 && a[al - 1] == '.') al--;
    while (bl > 0 && b[bl - 1] == '.') bl--;
    return al == bl && strncasecmp(a, b, al) == 0;
}

/* qo->glue_indomain のときは BIND named 9.18.41/9.20.15 以降と同様、NS のターゲットが
 * NS の owner 配下 (in-domain) の glue だけを採用し、それ以外 (sibling/unrelated) は
 * 無視して報告する。無視された NS 名は後段で解決される。 */
int trace_collect_glue(const uint8_t *pkt, size_t pkt_len, size_t *roff, int arcount,
                       char ns_names[][256], char ns_owners[][256], int ns_count,
                       const query_opts_t *qo, char out[][64], int count, int out_cap, bool report) {
    char ignored[16][256];
    int ignored_count = 0;
    for (int i = 0; i < arcount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(pkt, pkt_len, roff, &g_dag_arena, &rec, &type) != 0) break;
        bool want = false;
        if (type == 1 && (qo->pref_family == AF_UNSPEC || qo->pref_family == AF_INET)) want = true;
        if (type == 28 && (qo->pref_family == AF_UNSPEC || qo->pref_family == AF_INET6)) want = true;
        if (!want || rec.rdata_count == 0) continue;
        for (int j = 0; j < ns_count; j++) {
            if (strcasecmp(rec.name, ns_names[j]) != 0) continue;
            if (qo->glue_indomain && !trace_name_is_subdomain(ns_names[j], ns_owners[j])) {
                bool seen = false;
                for (int k = 0; k < ignored_count; k++) {
                    if (strcasecmp(ignored[k], ns_names[j]) == 0) { seen = true; break; }
                }
                if (!seen && ignored_count < 16) {
                    snprintf(ignored[ignored_count++], 256, "%s", ns_names[j]);
                    if (report) {
                        printf(";; ignoring out-of-domain glue for '%s' (NS of '%s')\n", ns_names[j], ns_owners[j]);
                    }
                }
                continue;
            }
            if (count < out_cap) {
                snprintf(out[count++], 64, "%s", rec.rdata[0]);
            }
            break;
        }
    }
    return count;
}
