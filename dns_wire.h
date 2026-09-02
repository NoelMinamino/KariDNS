#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// ============================================================================
// 数値フィールド安全パースヘルパー (0-255, 0-65535 範囲検証付き)
// ============================================================================
static inline bool parse_u8(const char *s, uint8_t *out) {
    if (!s || !*s) return false;
    char *endptr;
    long val = strtol(s, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 255) return false;
    if (out) *out = (uint8_t)val;
    return true;
}

static inline bool parse_u16(const char *s, uint16_t *out) {
    if (!s || !*s) return false;
    char *endptr;
    long val = strtol(s, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 65535) return false;
    if (out) *out = (uint16_t)val;
    return true;
}

// Forward declarations
struct server_config_s;

#define DNS_HEADER_SIZE 12

// ============================================================================
// ステータス構造体 (IPC用)
// ============================================================================
typedef struct {
    time_t boot_time;
    time_t last_configured_time;
    int num_zones;
    int xfers_running;
    int tcp_clients;
    int tcp_high_water;
    int worker_threads;
    char config_file[256];
    bool frontend_alive;
    bool query_logging;
    bool response_logging;
    uint64_t rrl_dropped;
    uint64_t rrl_slipped;
    uint64_t ede_proh;
    uint64_t ede_na;
    uint64_t ede_ns;
    uint64_t ede_oth;
} karidns_status_t;

// ============================================================================
// 定数 (dns_server_core.c から移動)
// ============================================================================
#define MAX_RDATA 48
#define MAX_JUMPS 16
#define COMPRESS_HASH_SIZE 4096
#define COMPRESS_HASH_MASK (COMPRESS_HASH_SIZE - 1)
#define MAX_PROBE_DEPTH 8
#define UDP_DEFAULT_MAX_RES_LEN 512

// ============================================================================
// 前方宣言 (zone_arena_t は dns_server_core.c 側で定義)
// ============================================================================
struct zone_arena_s;
typedef struct zone_arena_s zone_arena_t;
void *arena_alloc(zone_arena_t *arena, size_t size);

// ============================================================================
// 型定義 (dns_server_core.c から移動)
// ============================================================================

// DNSレコード構造体 (ゼロコピー指向)
typedef struct {
    char *name;
    char *ttl;
    char *class_str;
    uint16_t class_val;
    char *type;
    uint16_t type_code;
    uint32_t ttl_value;
    char *rdata[MAX_RDATA];
    int rdata_count;
    uint16_t generic_len;
    uint8_t *generic_data;
    int next_record; // Index of next record with same hash, -1 if none
    time_t tinydns_ttd;         /* 0 = timestampなし(全ゾーン共通デフォルト)。
                                   tinydns形式でtimestampフィールドが指定された場合のみ非0 */
    bool tinydns_ttl_countdown; /* true なら「ttl=0 + timestamp」のカウントダウンTTLレコード */
    
    bool is_cached;
    union {
        struct {
            struct in_addr addr;
        } a;
        struct {
            struct in6_addr addr;
        } aaaa;
        struct {
            char *mname;
            char *rname;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t minimum;
        } soa;
        struct {
            uint16_t pref;
            char *target;
        } mx;
        struct {
            uint16_t type_covered;
            uint8_t algorithm;
            uint8_t labels;
            uint32_t orig_ttl;
            uint32_t sig_exp;
            uint32_t sig_inc;
            uint16_t key_tag;
            char *signer;
            uint8_t *signature;
            size_t signature_len;
        } rrsig;
        struct {
            uint16_t priority;
            uint16_t weight;
            uint16_t port;
            char *target;
        } srv;
    } cache;
} dns_record_t;

// Cache preparse function
void dns_record_preparse_cache(struct zone_arena_s *arena, dns_record_t *rec);

// 名前圧縮用ハッシュエントリ
typedef struct {
    uint32_t hash;
    uint16_t offset;
    uint16_t generation;
} compress_entry_t;

// 名前圧縮コンテキスト
typedef struct {
    compress_entry_t table[COMPRESS_HASH_SIZE];
    uint16_t current_generation;
} compress_ctx_t;

// TSIG キー構造体
typedef struct tsig_key {
    char *name;
    char *algorithm;
    char *secret;
    uint8_t secret_decoded[256];
    size_t secret_decoded_len;
    int64_t fuzztime;
    struct tsig_key *next;
} tsig_key_t;

// Extended DNS Errors (RFC 8914) 最大パース数
// 異常系パケットやファジングテストで多数のEDEオプションが注入された場合でも
// 途中で切り落とさず確実に追尾・検証できるよう上限を64に設定している。
#define MAX_EDE_COUNT 64

typedef struct {
    uint16_t code;
    char text[256];
} parsed_ede_t;

typedef struct {
    bool present;
    uint16_t udp_payload_size;
    uint8_t ext_rcode;
    uint8_t version;
    bool dnssec_ok;
    bool compact_answers_ok;
    
    // DNS Cookie
    bool has_cookie;
    bool has_malformed_cookie;
    uint8_t client_cookie[8];
    uint8_t server_cookie[32];
    uint16_t server_cookie_len;
    
    // Extended DNS Errors (EDE)
    uint16_t ede_count;
    parsed_ede_t ede_list[MAX_EDE_COUNT];
    
    // NSID and Keepalive
    bool has_nsid_query;
    bool has_keepalive_query;
    
    // Multiple QTYPEs (RFC 10029)
    bool has_mqtype_query;
    bool mqtype_query_duplicated;
    bool saw_invalid_mqtype_response_in_query;
    uint16_t mqtypes[16];
    uint16_t mqtype_count;
} edns_info_t;

// ============================================================================
// 関数プロトタイプ
// ============================================================================

// 名前圧縮
void compress_ctx_init_packet(compress_ctx_t *ctx);
int compress_name(uint8_t *packet_buf, uint16_t *offset, const uint8_t *name, compress_ctx_t *ctx, size_t max_len);

// ワイヤーフォーマット名前操作
int skip_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset);
int expand_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, zone_arena_t *arena, char **name_out);

// レコード型変換・解析
const char *get_type_str(uint16_t type, zone_arena_t *arena);
int parse_resource_record(const uint8_t *packet, size_t packet_len, size_t *offset, zone_arena_t *arena, dns_record_t *rec, uint16_t *type_out);

// TSIG
bool tsig_algorithm_is_supported(const char *alg);
int const_time_memcmp(const void *a, const void *b, size_t len);
int tsig_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len, tsig_key_t *key, uint16_t tsig_error,
                     uint8_t *prior_mac, size_t *prior_mac_len,
                     const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                     bool is_subsequent);
// 注意: mac_out は最低 EVP_MAX_MD_SIZE (64) バイトを確保すること。
// mac_len_out には実際にコピーされたバイト数（<= EVP_MAX_MD_SIZE）が返る。
int tsig_verify_packet(const uint8_t *packet, size_t packet_len, tsig_key_t *key,
                       const uint8_t *prior_mac, size_t prior_mac_len,
                       const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                       bool is_subsequent,
                       uint8_t *mac_out /* >= EVP_MAX_MD_SIZE bytes */,
                       size_t *mac_len_out);

int extract_wire_name_to_buffer(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, char *buf, size_t buf_size);
long write_uncompressed_name(uint8_t *buf, size_t offset, size_t max_len, const char *name);
int write_dns_name_str(uint8_t *packet_buf, uint16_t *offset, const char *name, compress_ctx_t *ctx, size_t max_len);
int serialize_dns_record(uint8_t *res, size_t max_res_len, uint16_t *offset_ptr, dns_record_t *rec, compress_ctx_t *comp_ctx, const char *owner_name, uint32_t override_ttl);
uint32_t parse_ttl_value(const char *ttl_str);

// EDNS
int parse_edns_opt(const uint8_t *req, size_t req_len,
                   uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount,
                   edns_info_t *edns);
void assemble_edns_opt(uint8_t *res, size_t max_res_len,
                       uint16_t *offset_inout, uint16_t *arcount_inout,
                       edns_info_t *edns, uint8_t rcode_ext, bool is_tcp,
                       struct server_config_s *cfg);

int process_update_sections(const uint8_t *req, size_t req_len,
                             const char *zone_name,
                             zone_arena_t *standby,
                             int *out_prcount, int *out_upcount);

#endif // DNS_WIRE_H
