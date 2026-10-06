#include "dag_trace.h"
#include "dag_output_yaml.h"
#include "dag_trace_common.h"

typedef struct {
    const char *server;
    int port;
    bool is_system; /* @server ではなくシステムリゾルバを使う */
} ns_resolver_t;

/* NS 名のアドレス解決に使うリゾルバを決める。
 * BIND dig +trace は @server を最初の ". NS" 問い合わせにのみ使い、NS 名の解決は
 * システムリゾルバで行う。@198.41.0.4 のような権威専用サーバ (RA=0) に A/AAAA を
 * 再帰要求しても referral しか返らないため、その場合はシステムリゾルバへ切り替える。
 * @server が再帰応答する (RA=1) 場合は従来どおり @server (と -p) を使う。 */
static void choose_ns_resolver(ns_resolver_t *rsv, const char *eff_server, int port, bool server_ra) {
    rsv->server = eff_server;
    rsv->port = port;
    rsv->is_system = false;
    if (!server_ra) {
        const char *sys = get_system_resolver();
        if (sys && sys[0] != '\0' && strcmp(sys, eff_server) != 0) {
            rsv->server = sys;
            rsv->port = 53;
            rsv->is_system = true;
        }
    }
}

static int resolve_ns_addr_type(const char *ns_name, uint16_t qtype, const ns_resolver_t *rsv,
                                const query_opts_t *base_qo, bool use_tcp,
                                char out[][64], char out_names[][256], int count, int out_cap) {
    query_opts_t resolve_qo = *base_qo;
    resolve_qo.rd_flag = true;
    /* TSIG 鍵は @server 用なのでシステムリゾルバには付けない */
    if (rsv->is_system) resolve_qo.want_tsig = false;
    uint8_t res_qbuf[512];
    uint8_t res_req_mac[64];
    size_t res_req_mac_len = 0;
    size_t res_qlen = build_and_sign_query(res_qbuf, sizeof(res_qbuf), ns_name, qtype, &resolve_qo, res_req_mac, &res_req_mac_len);
    if (res_qlen == 0) return count;
    uint8_t res_resp[4096];
    ssize_t res_n = do_dns_exchange_auto(rsv->server, rsv->port, &resolve_qo, res_qbuf, res_qlen, res_resp, sizeof(res_resp), resolve_qo.timeout_sec, use_tcp);
    if (res_n <= 12) return count;
    int qd = (res_resp[4] << 8) | res_resp[5];
    int an = (res_resp[6] << 8) | res_resp[7];
    size_t roff = 12;
    for (int k = 0; k < qd; k++) {
        char *d;
        if (expand_wire_name(res_resp, res_n, roff, &roff, &g_dag_arena, &d) != 0) return count;
        roff += 4;
    }
    for (int k = 0; k < an; k++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(res_resp, res_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
        if (type == qtype && rec.rdata_count > 0 && count < out_cap) {
            if (out_names) snprintf(out_names[count], 256, "%s", ns_name);
            snprintf(out[count++], 64, "%s", rec.rdata[0]);
        }
    }
    return count;
}

/* NS 名群の A/AAAA を解決して out に集める。解決できなかった NS 名は dig と同様に報告する。 */
static int resolve_ns_addresses(char names[][256], int name_count, const ns_resolver_t *rsv,
                                const query_opts_t *base_qo, bool use_tcp,
                                char out[][64], char out_names[][256], int out_cap, bool report) {
    int count = 0;
    for (int j = 0; j < name_count && count < out_cap; j++) {
        int before = count;
        if (base_qo->pref_family == AF_UNSPEC || base_qo->pref_family == AF_INET) {
            count = resolve_ns_addr_type(names[j], 1 /* A */, rsv, base_qo, use_tcp, out, out_names, count, out_cap);
        }
        if (count < out_cap && (base_qo->pref_family == AF_UNSPEC || base_qo->pref_family == AF_INET6)) {
            count = resolve_ns_addr_type(names[j], 28 /* AAAA */, rsv, base_qo, use_tcp, out, out_names, count, out_cap);
        }
        if (count == before && report) {
            size_t nlen = strlen(names[j]);
            if (nlen > 1 && names[j][nlen - 1] == '.') nlen--;
            printf(";; couldn't get address for '%.*s' from %s#%d\n", (int)nlen, names[j], rsv->server, rsv->port);
        }
    }
    return count;
}

static int run_trace_query_impl(const char *qname, const char *server, const char *qtype_s, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, const query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt) {
    bool eff_use_tcp = (!force_udp && use_tcp);
    const char *eff_server = server ? server : get_system_resolver();
    display_opts_t trace_dopt = *dopt;
    trace_dopt.show_comments = false;
    trace_dopt.show_question = false;
    trace_dopt.show_stats = false;

    uint8_t *root_qbuf = malloc(65535);
    uint8_t *root_resp = malloc(65535);
    uint8_t *qbuf = malloc(65535);
    uint8_t *resp = malloc(65535);
    if (!root_qbuf || !root_resp || !qbuf || !resp) {
        fprintf(stderr, "Error: Failed to allocate memory for +trace buffers\n");
        free(root_qbuf);
        free(root_resp);
        free(qbuf);
        free(resp);
        return 1;
    }

    char current_qname[256];
    if (strlcpy(current_qname, qname, sizeof(current_qname)) >= sizeof(current_qname)) {
        fprintf(stderr, "Error: qname too long for +trace\n");
        free(root_qbuf);
        free(root_resp);
        free(qbuf);
        free(resp);
        return 1;
    }

    int ret = 0;

    char target_ips[32][64];
    char target_names[32][256]; /* target_ips[i] を持つ NS 名 (dig と同様に Received 行に表示する) */
    int target_count = 0;
    ns_resolver_t trace_rsv = { eff_server, port, false };

    query_opts_t root_qo = *qo;
    root_qo.rd_flag = true;
    uint8_t root_req_mac[64];
    size_t root_req_mac_len = 0;
    size_t root_qlen = build_and_sign_query(root_qbuf, 65535, ".", 2 /* NS */, &root_qo, root_req_mac, &root_req_mac_len);
    if (root_qlen == 0) {
        fprintf(stderr, "Error: Failed to construct root query for +trace\n");
        ret = 1;
        goto cleanup;
    }

    if (!no_hexdump_query && !dopt->yaml) {
        printf("Query (%zd bytes):\n", root_qlen);
        hexdump(root_qbuf, root_qlen);
        printf("\n");
    }

    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ssize_t root_n = do_dns_exchange_auto(eff_server, port, &root_qo, root_qbuf, root_qlen, root_resp, 65535, root_qo.timeout_sec, eff_use_tcp);
    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    if (root_n <= 0) {
        if (dopt->yaml) {
            printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
        } else {
            printf(";; connection timed out; no servers could be reached\n");
        }
        ret = 9;
        goto cleanup;
    }

    int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
    trace_record_result(eff_server, root_n, root_resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
    if (!no_hexdump_response && !dopt->yaml) {
        printf("Response (%zd bytes):\n", root_n);
        hexdump(root_resp, (size_t)root_n);
        printf("\n");
    }

    if (root_n > 12) {
        if (root_qo.want_tsig) {
            uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
            int terr = tsig_verify_packet(root_resp, (size_t)root_n, &root_qo.tsig_key, root_req_mac, root_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
            print_tsig_verify_error(terr, root_resp, (size_t)root_n);
        }
        if (dopt->yaml) {
            print_response_yaml(root_resp, root_n, eff_server, port, eff_use_tcp, dopt);
        } else {
            axfr_state_t dummy_axfr = {0};
            print_response(root_resp, root_n, &dummy_axfr, &trace_dopt);
            int dt_ms_root = timespec_diff_ms(&start_ts, &end_ts);
            /* dig: "from ADDR#PORT(@server に指定した名前)" */
            trace_print_received(root_n, g_last_server_ip[0] ? g_last_server_ip : eff_server, port, eff_server, dt_ms_root);
        }

        size_t offset = 12;
        int r_qd = (root_resp[4] << 8) | root_resp[5];
        int r_an = (root_resp[6] << 8) | root_resp[7];
        int r_ns = (root_resp[8] << 8) | root_resp[9];
        int r_ar = (root_resp[10] << 8) | root_resp[11];
        for (int i = 0; i < r_qd; i++) {
            char *d;
            if (expand_wire_name(root_resp, root_n, offset, &offset, &g_dag_arena, &d) != 0) break;
            offset += 4;
        }

        char rns_names[32][256];
        char rns_owners[32][256];
        int rns_count = 0;
        trace_collect_rrs_by_type(root_resp, root_n, &offset, r_an, 2 /* NS */, rns_names, rns_owners, &rns_count, 32);
        trace_collect_rrs_by_type(root_resp, root_n, &offset, r_ns, 2 /* NS */, rns_names, rns_owners, &rns_count, 32);
        /* +noglue (default, BIND 9.20+ dig compatible): ADDITIONAL section is ignored and
         * nameserver addresses are resolved via the configured resolver below.
         * +glue: legacy behavior, use A/AAAA from ADDITIONAL first.
         * +glue=indomain: use only in-domain glue (BIND named 9.18.41/9.20.15+). */
        if (root_qo.use_glue) {
            target_count = trace_collect_glue(root_resp, root_n, &offset, r_ar, rns_names, rns_owners, rns_count,
                                        &root_qo, target_ips, target_names, target_count, 32, !dopt->yaml);
        }

        if (rns_count > 0) {
            /* @server が再帰応答しない (RA=0, 例: @198.41.0.4) 場合は dig と同様に
             * システムリゾルバで NS 名を解決する。 */
            ns_resolver_t rsv;
            choose_ns_resolver(&rsv, eff_server, port, (root_resp[3] & 0x80) != 0);
            if (target_count == 0) {
                target_count = resolve_ns_addresses(rns_names, rns_count, &rsv, &root_qo, eff_use_tcp,
                                                    target_ips, target_names, 32, !dopt->yaml);
            }
            trace_rsv = rsv;
        }
    }

    if (target_count == 0) {
        if (root_n > 12 && !dopt->yaml) {
            printf(";; No root nameserver addresses %s, stopping trace.\n",
                   root_qo.use_glue ? "found" : "resolved");
        }
        ret = 0;
        goto cleanup;
    }

    query_opts_t hop_qo = *qo;
    hop_qo.rd_flag = false;

    for (int hop = 1; hop < 32 && target_count > 0; hop++) {
        reset_dag_arena();
        size_t qlen = 0;
        uint8_t hop_req_mac[64];
        size_t hop_req_mac_len = 0;
        if (hex_payload) {
            qlen = parse_hex_string(hex_payload, qbuf, 65535);
            if (qlen == 0 || qlen > 65535) {
                fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max 65535 bytes)\n");
                ret = 1;
                goto cleanup;
            }
        } else {
            int qtype_val = parse_qtype(qtype_s);
            if (qtype_val < 0) {
                ret = 1;
                goto cleanup;
            }
            qlen = build_and_sign_query(qbuf, 65535, current_qname, (uint16_t)qtype_val, &hop_qo, hop_req_mac, &hop_req_mac_len);
            if (qlen == 0) break;
        }

        ssize_t n = -1;
        int active_target_idx = 0;

        for (int ti = 0; ti < target_count; ti++) {
            if (!no_hexdump_query && !dopt->yaml) {
                printf("Query (%zd bytes):\n", qlen);
                hexdump(qbuf, qlen);
                printf("\n");
            }
            clock_gettime(CLOCK_MONOTONIC, &start_ts);
            n = do_dns_exchange_auto(target_ips[ti], port, &hop_qo, qbuf, qlen, resp, 65535, hop_qo.timeout_sec, eff_use_tcp);
            clock_gettime(CLOCK_MONOTONIC, &end_ts);
            if (n > 0) {
                active_target_idx = ti;
                break;
            }
            if (dopt->yaml) {
                printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
            } else {
                printf(";; connection to %s#%d timed out; trying next server...\n", target_ips[ti], port);
            }
        }

        if (n <= 0) {
            if (dopt->yaml) {
                printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
            } else {
                printf(";; no servers could be reached for hop %d\n", hop);
            }
            ret = 9;
            goto cleanup;
        }

        int dt_ms_hop = timespec_diff_ms(&start_ts, &end_ts);
        trace_record_result(target_ips[active_target_idx], n, resp, dt_ms_hop, eff_use_tcp ? "TCP" : "UDP");

        if (!no_hexdump_response && !dopt->yaml) {
            printf("Response (%zd bytes):\n", n);
            hexdump(resp, (size_t)n);
            printf("\n");
        }

        if (n > 12 && hop_qo.want_tsig) {
            uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
            int terr = tsig_verify_packet(resp, (size_t)n, &hop_qo.tsig_key, hop_req_mac, hop_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
            print_tsig_verify_error(terr, resp, (size_t)n);
        }

        if (dopt->yaml) {
            print_response_yaml(resp, n, target_ips[active_target_idx], port, eff_use_tcp, dopt);
        } else {
            axfr_state_t dummy_axfr = {0};
            print_response(resp, n, &dummy_axfr, &trace_dopt);
            trace_print_received(n, target_ips[active_target_idx], port, target_names[active_target_idx], dt_ms_hop);
        }

        if (n < 12) break;
        int flags = (resp[2] << 8) | resp[3];
        int ancount = (resp[6] << 8) | resp[7];
        int nscount = (resp[8] << 8) | resp[9];
        int arcount = (resp[10] << 8) | resp[11];
        int rcode = flags & 0x0F;

        /* 回答 (CNAME を含む) またはエラーで終わる。BIND dig +trace と同様に CNAME の先は辿らない
         * (連鎖を辿るのは +trace2)。 */
        if (ancount > 0 || rcode != 0) break;

        if (nscount == 0) break;

        size_t offset = 12;
        int qdcount = (resp[4] << 8) | resp[5];
        for (int i = 0; i < qdcount; i++) {
            char *dummy;
            if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) break;
            offset += 4;
        }

        char ns_names[16][256];
        char ns_owners[16][256];
        int ns_count = 0;
        trace_collect_rrs_by_type(resp, n, &offset, nscount, 2 /* NS */, ns_names, ns_owners, &ns_count, 16);

        int new_target_count = 0;
        char new_target_ips[16][64];
        char new_target_names[16][256];
        if (hop_qo.use_glue) {
            new_target_count = trace_collect_glue(resp, n, &offset, arcount, ns_names, ns_owners, ns_count,
                                            &hop_qo, new_target_ips, new_target_names, 0, 16, !dopt->yaml);
        }

        if (new_target_count == 0 && ns_count > 0) {
            new_target_count = resolve_ns_addresses(ns_names, ns_count, &trace_rsv, &hop_qo, eff_use_tcp,
                                                    new_target_ips, new_target_names, 16, !dopt->yaml);
        }

        if (new_target_count == 0) {
            if (!dopt->yaml) {
                if (hop_qo.use_glue) {
                    printf(";; No glue found for next hop, stopping trace.\n");
                } else {
                    printf(";; No nameserver addresses resolved for next hop, stopping trace.\n");
                }
            }
            break;
        }

        target_count = new_target_count;
        _Static_assert(sizeof(target_ips[0]) == sizeof(new_target_ips[0]), "buffer size mismatch");
        for(int i=0; i<target_count; i++) {
            if (strlcpy(target_ips[i], new_target_ips[i], sizeof(target_ips[i])) >= sizeof(target_ips[i])) {
                fprintf(stderr, "warning: target IP truncated\n");
            }
            memcpy(target_names[i], new_target_names[i], sizeof(target_names[i]));
        }
    } // end hop loop

cleanup:
    free(root_qbuf);
    free(root_resp);
    free(qbuf);
    free(resp);
    return ret;
}

int run_trace_query(const char *qname, const char *server, const char *qtype_s, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, const query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt) {
    return run_trace_query_impl(qname, server, qtype_s, port, use_tcp, force_udp, no_hexdump_query, no_hexdump_response, qo, hex_payload, dopt);
}

int run_nssearch(const char *qname, const char *server, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    (void)dopt;
    bool eff_use_tcp = (!force_udp && use_tcp);
    const char *eff_server = server ? server : get_system_resolver();
    query_opts_t ns_qo = qo;
    ns_qo.rd_flag = true;
    uint8_t qbuf[65535];
    uint8_t ns_req_mac[64];
    size_t ns_req_mac_len = 0;
    size_t qlen = build_and_sign_query(qbuf, sizeof(qbuf), qname, 2 /* NS */, &ns_qo, ns_req_mac, &ns_req_mac_len);
    if (!no_hexdump_query) {
        printf("Query (%zd bytes):\n", qlen);
        hexdump(qbuf, qlen);
        printf("\n");
    }
    uint8_t resp[65535];
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ssize_t n = do_dns_exchange_auto(eff_server, port, &ns_qo, qbuf, qlen, resp, sizeof(resp), ns_qo.timeout_sec, eff_use_tcp);
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    if (n > 0) {
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        trace_record_result(eff_server, n, resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
        if (!no_hexdump_response) {
            printf("Response (%zd bytes):\n", n);
            hexdump(resp, (size_t)n);
            printf("\n");
        }
    }
    if (n <= 0) {
        printf(";; connection timed out; no servers could be reached\n");
        return 9;
    }
    
    if (n < 12) return 1;

    if (ns_qo.want_tsig) {
        uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
        int terr = tsig_verify_packet(resp, (size_t)n, &ns_qo.tsig_key, ns_req_mac, ns_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
        print_tsig_verify_error(terr, resp, (size_t)n);
    }
    int qdcount = (resp[4] << 8) | resp[5];
    int ancount = (resp[6] << 8) | resp[7];
    int nscount = (resp[8] << 8) | resp[9];
    int arcount = (resp[10] << 8) | resp[11];
    
    size_t offset = 12;
    for (int i = 0; i < qdcount; i++) {
        char *dummy;
        if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) return 1;
        offset += 4;
    }
    
    char ns_names[32][256];
    int ns_count = 0;
    int an_parsed = 0;
    for (; an_parsed < ancount; an_parsed++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
            snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
        }
    }
    int ns_parsed = 0;
    for (; ns_parsed < nscount; ns_parsed++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
            snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
        }
    }

    if (ns_count == 0) {
        printf(";; no NS records found for %s\n", qname);
        return 1;
    }

    struct { char ns_name[256]; char ip[64]; } all_ns_ips[128];
    int all_ns_count = 0;
    bool ns_has_glue[32] = {false};

    // Scan remaining records up to ADDITIONAL section
    for (int i = an_parsed; i < ancount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
    }
    for (int i = ns_parsed; i < nscount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
    }

    // Scan ADDITIONAL section for glue A/AAAA records (if +glue is active)
    if (qo.use_glue) {
        for (int i = 0; i < arcount; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
            bool want = false;
            if (type == 1 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET)) want = true;
            if (type == 28 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET6)) want = true;
            if (want && rec.rdata_count > 0) {
                for (int j = 0; j < ns_count; j++) {
                    if (strcasecmp(rec.name, ns_names[j]) == 0) {
                        if (qo.glue_indomain && !trace_name_is_subdomain(ns_names[j], qname)) continue;
                        ns_has_glue[j] = true;
                        bool duplicate = false;
                        for (int d = 0; d < all_ns_count; d++) {
                            if (strcmp(all_ns_ips[d].ip, rec.rdata[0]) == 0) { duplicate = true; break; }
                        }
                        if (!duplicate && all_ns_count < 128) {
                            snprintf(all_ns_ips[all_ns_count].ns_name, sizeof(all_ns_ips[all_ns_count].ns_name), "%s", ns_names[j]);
                            snprintf(all_ns_ips[all_ns_count].ip, sizeof(all_ns_ips[all_ns_count].ip), "%s", rec.rdata[0]);
                            all_ns_count++;
                        }
                    }
                }
            }
        }
    }

    // Resolve out-of-bailiwick NS names without glue using getaddrinfo
    for (int j = 0; j < ns_count; j++) {
        if (ns_has_glue[j]) continue;
        char clean_name[256];
        snprintf(clean_name, sizeof(clean_name), "%s", ns_names[j]);
        size_t c_len = strlen(clean_name);
        if (c_len > 1 && clean_name[c_len - 1] == '.') {
            clean_name[c_len - 1] = '\0';
        }

        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = qo.pref_family;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(clean_name, NULL, &hints, &res) == 0 && res != NULL) {
            for (struct addrinfo *p = res; p != NULL && all_ns_count < 128; p = p->ai_next) {
                char ip_str[64];
                if (p->ai_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                } else if (p->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p->ai_addr;
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
                } else {
                    continue;
                }
                bool duplicate = false;
                for (int d = 0; d < all_ns_count; d++) {
                    if (strcmp(all_ns_ips[d].ip, ip_str) == 0) { duplicate = true; break; }
                }
                if (!duplicate) {
                    snprintf(all_ns_ips[all_ns_count].ns_name, sizeof(all_ns_ips[all_ns_count].ns_name), "%s", ns_names[j]);
                    snprintf(all_ns_ips[all_ns_count].ip, sizeof(all_ns_ips[all_ns_count].ip), "%s", ip_str);
                    all_ns_count++;
                }
            }
            freeaddrinfo(res);
        } else {
            fprintf(stderr, "couldn't get address for '%s': failure\n", clean_name);
        }
    }

    if (all_ns_count == 0) {
        char clean_first[256];
        snprintf(clean_first, sizeof(clean_first), "%s", ns_names[0]);
        size_t c_len = strlen(clean_first);
        if (c_len > 0 && clean_first[c_len - 1] == '.') clean_first[c_len - 1] = '\0';
        fprintf(stderr, "dig: couldn't get address for '%s': no more\n", clean_first);
        return 9;
    }

    for (int k = 0; k < all_ns_count; k++) {
        size_t slen = 0;
        uint8_t soa_req_mac[64];
        size_t soa_req_mac_len = 0;
        if (hex_payload) {
            slen = parse_hex_string(hex_payload, qbuf, sizeof(qbuf));
            if (slen == 0 || slen > sizeof(qbuf)) {
                fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max %zu bytes)\n", sizeof(qbuf));
                return 1;
            }
        } else {
            slen = build_and_sign_query(qbuf, sizeof(qbuf), qname, 6 /* SOA */, &qo, soa_req_mac, &soa_req_mac_len);
        }
        if (!no_hexdump_query) {
            printf("Query (%zd bytes):\n", slen);
            hexdump(qbuf, slen);
            printf("\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        ssize_t sn = do_dns_exchange_auto(all_ns_ips[k].ip, port, &qo, qbuf, slen, resp, sizeof(resp), qo.timeout_sec, eff_use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        int dt_ms = 0;
        if (sn > 0) {
            dt_ms = timespec_diff_ms(&start_ts, &end_ts);
            trace_record_result(all_ns_ips[k].ip, sn, resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
            if (!no_hexdump_response) {
                printf("Response (%zd bytes):\n", sn);
                hexdump(resp, (size_t)sn);
                printf("\n");
            }
        }
        if (sn > 12) {
            if (qo.want_tsig) {
                uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
                int terr = tsig_verify_packet(resp, (size_t)sn, &qo.tsig_key, soa_req_mac, soa_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
                print_tsig_verify_error(terr, resp, (size_t)sn);
            }
            int sancount = (resp[6] << 8) | resp[7];
            size_t soff = 12;
            int sqdcount = (resp[4] << 8) | resp[5];
            for (int i = 0; i < sqdcount; i++) {
                char *d;
                if (expand_wire_name(resp, sn, soff, &soff, &g_dag_arena, &d) != 0) break;
                soff += 4;
            }
            for (int i=0; i<sancount; i++) {
                dns_record_t rec; uint16_t type;
                if (parse_resource_record(resp, sn, &soff, &g_dag_arena, &rec, &type) != 0) break;
                if (type == 6 && rec.rdata_count >= 7) {
                    printf("SOA %s %s %s %s %s %s %s from server %s in %d ms\n",
                           rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3], rec.rdata[4], rec.rdata[5], rec.rdata[6],
                           all_ns_ips[k].ip, dt_ms);
                    break;
                }
            }
        } else {
            printf(";; connection timed out; no servers could be reached\n");
        }
    }
    return 0;
}
