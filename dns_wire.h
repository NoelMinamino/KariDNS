#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// 定数 (dns_server_core.c から移動)
// ============================================================================
#define MAX_RDATA 48
#define MAX_JUMPS 16
#define COMPRESS_HASH_SIZE 4096
#define COMPRESS_HASH_MASK (COMPRESS_HASH_SIZE - 1)
#define MAX_PROBE_DEPTH 8

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
    char *type;
    uint16_t type_code;
    char *rdata[MAX_RDATA];
    int rdata_count;
    uint16_t generic_len;
    uint8_t *generic_data;
    int next_record; // Index of next record with same hash, -1 if none
} dns_record_t;

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
    struct tsig_key *next;
} tsig_key_t;

// ============================================================================
// 関数プロトタイプ
// ============================================================================

// 名前圧縮
void compress_ctx_init_packet(compress_ctx_t *ctx);
int compress_name(uint8_t *packet_buf, uint16_t *offset, const uint8_t *name, compress_ctx_t *ctx);

// ワイヤーフォーマット名前操作
int skip_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset);
int expand_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, zone_arena_t *arena, char **name_out);

// レコード型変換・解析
const char *get_type_str(uint16_t type, zone_arena_t *arena);
int parse_resource_record(const uint8_t *packet, size_t packet_len, size_t *offset, zone_arena_t *arena, dns_record_t *rec, uint16_t *type_out);

// TSIG
int tsig_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len, tsig_key_t *key, uint16_t tsig_error, uint8_t *prior_mac, size_t *prior_mac_len);
int tsig_verify_packet(const uint8_t *packet, size_t packet_len, tsig_key_t *key);

// DNSレスポンス組み立て
size_t write_uncompressed_name(uint8_t *buf, const char *name);
int write_dns_name_str(uint8_t *packet_buf, uint16_t *offset, const char *name, compress_ctx_t *ctx);
int serialize_dns_record(uint8_t *res, size_t max_res_len, uint16_t *offset_ptr, dns_record_t *rec, compress_ctx_t *comp_ctx, const char *owner_name, uint32_t override_ttl);

// EDNS
void parse_edns_opt(const uint8_t *req, size_t req_len,
                    uint16_t qdcount, uint16_t ancount_req,
                    uint16_t nscount_req, uint16_t arcount_req,
                    bool *has_edns_out, uint16_t *client_payload_size_out);
void assemble_edns_opt(uint8_t *res, size_t max_res_len,
                       uint16_t *offset_inout, uint16_t *arcount_inout);

#endif // DNS_WIRE_H
