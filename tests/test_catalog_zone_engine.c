#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_catalog_zone.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_utils.h"

// Mock globals
int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
int g_cwd_fd = -1;
char g_startup_cwd[PATH_MAX] = "";

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

server_config_t *acquire_config_snapshot(void) {
    return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}
void release_config_snapshot(server_config_t *snap) { (void)snap; }

int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    (void)family; (void)type; (void)addr; (void)addr_len; return -1;
}

ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
    (void)fd; (void)buf; return len;
}

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out) {
    (void)fd; (void)ctx; (void)msg_out; (void)msg_len_out; return -1;
}

void submit_response_log(log_action_t action, const char *client_ip, int client_port,
                        const char *qname, uint16_t qclass, uint16_t qtype,
                        uint8_t rcode, bool has_edns, bool dnssec_ok) {
    (void)action; (void)client_ip; (void)client_port; (void)qname;
    (void)qclass; (void)qtype; (void)rcode; (void)has_edns; (void)dnssec_ok;
}

void dec_tcp_clients(void) {}
void inc_tcp_clients(void) {}

size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out) {
    (void)ip; (void)port; (void)out; return 0;
}

static void test_catalog_hashing_and_bookkeeping(void) {
    printf("[TEST] Catalog Zone: calc_catalog_member_hash & remove_member_from_catalog_bookkeeping...\n");

    uint32_t h1 = calc_catalog_member_hash("member.example.com", "uid1");
    uint32_t h2 = calc_catalog_member_hash("member.example.com", "uid2");
    uint32_t h3 = calc_catalog_member_hash("member.example.com", NULL);
    assert(h1 != h2);
    assert(h1 != h3);

    // Bookkeeping removal
    zone_db_entry_t cat_entry;
    memset(&cat_entry, 0, sizeof(cat_entry));
    cat_entry.catalog_member_count = 3;
    cat_entry.catalog_members = calloc(3, sizeof(catalog_member_id_t));

    strcpy(cat_entry.catalog_members[0].domain, "m1.example.com.");
    strcpy(cat_entry.catalog_members[0].unique_id, "u1");
    cat_entry.catalog_members[0].group_count = 1;
    cat_entry.catalog_members[0].groups = malloc(sizeof(char *));
    cat_entry.catalog_members[0].groups[0] = strdup("group1");

    strcpy(cat_entry.catalog_members[1].domain, "m2.example.com.");
    strcpy(cat_entry.catalog_members[1].unique_id, "u2");

    strcpy(cat_entry.catalog_members[2].domain, "m3.example.com.");
    strcpy(cat_entry.catalog_members[2].unique_id, "u3");

    // Remove middle element (m2)
    remove_member_from_catalog_bookkeeping(&cat_entry, "u2", "m2.example.com.");
    assert(cat_entry.catalog_member_count == 2);
    assert(strcmp(cat_entry.catalog_members[0].unique_id, "u1") == 0);
    assert(strcmp(cat_entry.catalog_members[1].unique_id, "u3") == 0);

    // Remove first element (with groups)
    remove_member_from_catalog_bookkeeping(&cat_entry, "u1", "m1.example.com.");
    assert(cat_entry.catalog_member_count == 1);
    assert(strcmp(cat_entry.catalog_members[0].unique_id, "u3") == 0);

    free(cat_entry.catalog_members);
    printf("  -> Bookkeeping removal passed.\n");
}

static void test_catalog_process_membership_rfc9432(void) {
    printf("[TEST] Catalog Zone: catalog_process_membership RFC 9432 validations...\n");

    zone_db_entry_t cat_entry;
    memset(&cat_entry, 0, sizeof(cat_entry));
    strncpy(cat_entry.domain, "catalog.example", sizeof(cat_entry.domain) - 1);

    zone_config_t cat_cfg;
    memset(&cat_cfg, 0, sizeof(cat_cfg));
    cat_cfg.domain = "catalog.example";
    cat_cfg.is_catalog = true;

    // 1. Missing version.<catalog> TXT "2" -> Aborts
    zone_arena_t a_no_ver;
    memset(&a_no_ver, 0, sizeof(a_no_ver));
    zone_arena_init(&a_no_ver);
    atomic_store_explicit(&cat_entry.rcu.active, &a_no_ver, memory_order_release);

    catalog_process_membership(&cat_entry, &cat_cfg, "default");
    assert(cat_entry.catalog_member_count == 0);

    // 2. Broken catalog (RFC 9432 §5.1): Multiple PTRs on same unique-N node
    zone_arena_t a_dup_ptr;
    memset(&a_dup_ptr, 0, sizeof(a_dup_ptr));
    zone_arena_init(&a_dup_ptr);
    a_dup_ptr.records = malloc(sizeof(dns_record_t) * 8);
    a_dup_ptr.records_cap = 8;

    // version.catalog.example. TXT "2"
    dns_record_t r_ver; memset(&r_ver, 0, sizeof(r_ver));
    r_ver.name = arena_strdup(&a_dup_ptr, "version.catalog.example.");
    r_ver.type_code = 16; r_ver.rdata_count = 1;
    r_ver.rdata[0] = arena_strdup(&a_dup_ptr, "2");
    a_dup_ptr.records[a_dup_ptr.count++] = r_ver;

    // node1.zones.catalog.example. PTR m1.example.
    dns_record_t r_p1; memset(&r_p1, 0, sizeof(r_p1));
    r_p1.name = arena_strdup(&a_dup_ptr, "node1.zones.catalog.example.");
    r_p1.type_code = 12; r_p1.rdata_count = 1;
    r_p1.rdata[0] = arena_strdup(&a_dup_ptr, "m1.example.");
    a_dup_ptr.records[a_dup_ptr.count++] = r_p1;

    // node1.zones.catalog.example. PTR m2.example. (Duplicate PTR on same node!)
    dns_record_t r_p2; memset(&r_p2, 0, sizeof(r_p2));
    r_p2.name = arena_strdup(&a_dup_ptr, "node1.zones.catalog.example.");
    r_p2.type_code = 12; r_p2.rdata_count = 1;
    r_p2.rdata[0] = arena_strdup(&a_dup_ptr, "m2.example.");
    a_dup_ptr.records[a_dup_ptr.count++] = r_p2;

    atomic_store_explicit(&cat_entry.rcu.active, &a_dup_ptr, memory_order_release);
    catalog_process_membership(&cat_entry, &cat_cfg, "default");
    assert(cat_entry.catalog_member_count == 0); // Broken catalog rejected!

    // 3. Broken catalog (RFC 9432 §5.1): Multiple unique-N pointing to same target domain
    zone_arena_t a_dup_target;
    memset(&a_dup_target, 0, sizeof(a_dup_target));
    zone_arena_init(&a_dup_target);
    a_dup_target.records = malloc(sizeof(dns_record_t) * 8);
    a_dup_target.records_cap = 8;
    a_dup_target.records[a_dup_target.count++] = r_ver;

    dns_record_t r_u1; memset(&r_u1, 0, sizeof(r_u1));
    r_u1.name = arena_strdup(&a_dup_target, "node1.zones.catalog.example.");
    r_u1.type_code = 12; r_u1.rdata_count = 1;
    r_u1.rdata[0] = arena_strdup(&a_dup_target, "same.example.");
    a_dup_target.records[a_dup_target.count++] = r_u1;

    dns_record_t r_u2; memset(&r_u2, 0, sizeof(r_u2));
    r_u2.name = arena_strdup(&a_dup_target, "node2.zones.catalog.example.");
    r_u2.type_code = 12; r_u2.rdata_count = 1;
    r_u2.rdata[0] = arena_strdup(&a_dup_target, "same.example.");
    a_dup_target.records[a_dup_target.count++] = r_u2;

    atomic_store_explicit(&cat_entry.rcu.active, &a_dup_target, memory_order_release);
    catalog_process_membership(&cat_entry, &cat_cfg, "default");
    assert(cat_entry.catalog_member_count == 0); // Duplicate target domain rejected!

    // 4. Static config collision skipping
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    zone_config_t static_z;
    memset(&static_z, 0, sizeof(static_z));
    static_z.domain = "static.example.";
    cfg.zones = &static_z;
    atomic_store_explicit(&g_config_db.active, &cfg, memory_order_release);

    zone_arena_t a_static_col;
    memset(&a_static_col, 0, sizeof(a_static_col));
    zone_arena_init(&a_static_col);
    a_static_col.records = malloc(sizeof(dns_record_t) * 8);
    a_static_col.records_cap = 8;
    a_static_col.records[a_static_col.count++] = r_ver;

    dns_record_t r_col; memset(&r_col, 0, sizeof(r_col));
    r_col.name = arena_strdup(&a_static_col, "node1.zones.catalog.example.");
    r_col.type_code = 12; r_col.rdata_count = 1;
    r_col.rdata[0] = arena_strdup(&a_static_col, "static.example.");
    a_static_col.records[a_static_col.count++] = r_col;

    atomic_store_explicit(&cat_entry.rcu.active, &a_static_col, memory_order_release);
    catalog_process_membership(&cat_entry, &cat_cfg, "default");
    assert(cat_entry.catalog_member_count == 0); // Colliding member skipped!

    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    zone_arena_destroy(&a_no_ver);
    zone_arena_destroy(&a_dup_ptr);
    zone_arena_destroy(&a_dup_target);
    zone_arena_destroy(&a_static_col);

    printf("  -> catalog_process_membership validations passed.\n");
}

static void test_find_catalog_parent_and_valid_properties(void) {
    printf("[TEST] Catalog Zone: find_catalog_parent_in_snapshot & valid member properties...\n");

    zone_db_entry_t cat_parent;
    memset(&cat_parent, 0, sizeof(cat_parent));
    strlcpy(cat_parent.domain, "catalog.example.", sizeof(cat_parent.domain));

    zone_db_entry_t other_z;
    memset(&other_z, 0, sizeof(other_z));
    strlcpy(other_z.domain, "other.example.", sizeof(other_z.domain));

    zone_db_entry_t *entries[2] = {&cat_parent, &other_z};
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 2;

    // 1. Without hash table (linear scan fallback)
    zone_db_entry_t *found = find_catalog_parent_in_snapshot(&view, "CATALOG.EXAMPLE.");
    assert(found == &cat_parent);
    found = find_catalog_parent_in_snapshot(&view, "nonexistent.catalog.");
    assert(found == NULL);
    assert(find_catalog_parent_in_snapshot(NULL, "catalog.example.") == NULL);
    assert(find_catalog_parent_in_snapshot(&view, NULL) == NULL);

    // 2. With hash table
    int hash_tbl[4] = {-1, -1, -1, -1};
    int chain_nxt[2] = {-1, -1};
    uint32_t h = calc_fnv1a_str("catalog.example.") & 3;
    hash_tbl[h] = 0;
    view.hash_table = hash_tbl;
    view.hash_size = 4;
    view.chain_next = chain_nxt;

    found = find_catalog_parent_in_snapshot(&view, "catalog.example.");
    assert(found == &cat_parent);

    // 3. Valid member processing with group property
    zone_config_t cat_cfg;
    memset(&cat_cfg, 0, sizeof(cat_cfg));
    cat_cfg.domain = "catalog.example.";
    cat_cfg.is_catalog = true;

    zone_arena_t a_valid;
    zone_arena_init(&a_valid);
    a_valid.records = calloc(8, sizeof(dns_record_t));
    a_valid.records_cap = 8;

    dns_record_t r_ver;
    memset(&r_ver, 0, sizeof(r_ver));
    r_ver.name = arena_strdup(&a_valid, "version.catalog.example.");
    r_ver.type_code = 16;
    r_ver.rdata_count = 1;
    r_ver.rdata[0] = arena_strdup(&a_valid, "2");
    a_valid.records[a_valid.count++] = r_ver;

    dns_record_t r_ptr;
    memset(&r_ptr, 0, sizeof(r_ptr));
    r_ptr.name = arena_strdup(&a_valid, "unique1.zones.catalog.example.");
    r_ptr.type_code = 12;
    r_ptr.rdata_count = 1;
    r_ptr.rdata[0] = arena_strdup(&a_valid, "member1.example.");
    a_valid.records[a_valid.count++] = r_ptr;

    dns_record_t r_grp;
    memset(&r_grp, 0, sizeof(r_grp));
    r_grp.name = arena_strdup(&a_valid, "group.unique1.zones.catalog.example.");
    r_grp.type_code = 16;
    r_grp.rdata_count = 1;
    r_grp.rdata[0] = arena_strdup(&a_valid, "edge-nodes");
    a_valid.records[a_valid.count++] = r_grp;

    dns_record_t r_coo;
    memset(&r_coo, 0, sizeof(r_coo));
    r_coo.name = arena_strdup(&a_valid, "coo.unique1.zones.catalog.example.");
    r_coo.type_code = 12;
    r_coo.rdata_count = 1;
    r_coo.rdata[0] = arena_strdup(&a_valid, "newcatalog.example.");
    a_valid.records[a_valid.count++] = r_coo;

    atomic_store_explicit(&cat_parent.rcu.active, &a_valid, memory_order_release);
    catalog_process_membership(&cat_parent, &cat_cfg, "default");

    // Clean up
    zone_arena_destroy(&a_valid);
    if (cat_parent.catalog_members) {
        free_catalog_member_ids(cat_parent.catalog_members, cat_parent.catalog_member_count);
        cat_parent.catalog_members = NULL;
        cat_parent.catalog_member_count = 0;
    }

    printf("  -> find_catalog_parent_and_valid_properties passed.\n");
}

int main(void) {
    printf("=== Starting Catalog Zone Engine Unit Tests ===\n");
    test_catalog_hashing_and_bookkeeping();
    test_catalog_process_membership_rfc9432();
    test_find_catalog_parent_and_valid_properties();
    printf("=== All Catalog Zone Engine Unit Tests PASSED ===\n");
    return 0;
}
