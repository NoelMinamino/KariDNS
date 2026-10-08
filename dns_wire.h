#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "dns_cidr.h"

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

/* WKS の PROTOCOL (RFC 1035 §3.4.2: マスターファイルでは名前か 10 進数)。名前は WKS の用途である
 * TCP と UDP (大文字小文字を区別しない、BIND と同じ) だけ。シリアライザと karicheck が共有する (K-03)。 */
static inline bool dns_wks_protocol_from_text(const char *s, uint8_t *out) {
    if (s && strcasecmp(s, "TCP") == 0) {
        if (out) *out = 6;
        return true;
    }
    if (s && strcasecmp(s, "UDP") == 0) {
        if (out) *out = 17;
        return true;
    }
    return parse_u8(s, out);
}

/* WKS のポート (RFC 1035 §3.4.2: 名前か 10 進数)。名前は固定表で引く (X-38)。シリアライザと karicheck が共有する。 */
bool dns_wks_port_from_text(const char *s, uint8_t proto, uint16_t *out);

// Forward declarations
struct server_config_s;
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

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
    uint64_t dnstap_truncated;
    /* D-12: 動いている karidns 自身の値 (起動時に取得)。karictl のローカルの値ではない */
    char version[32];
    char hostname[256];
    char os_name[64];
    char os_release[64];
    char machine[64];
    int ncpus;
} karidns_status_t;

// ============================================================================
// 定数 (dns_server_core.c から移動)
// ============================================================================
#define MAX_RDATA 48
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
// KariDNS 拡張定数 (Private Use 範囲: RFC 6895 / IANA DNS Parameters)
// ============================================================================
#define DNS_CLASS_KARIDNS_EXT           65302
#define DNS_TYPE_KARIDNS_LOC_STATE      65401
#define DNS_TYPE_KARIDNS_ECS_STATE      65402
#define DNS_TYPE_KARIDNS_LOC_TAGDEF     65403
#define DNS_TYPE_KARIDNS_ECS_TAGDEF     65404
#define DNS_TYPE_KARIDNS_TINYDNS_LOCDEF 65405
#define DNS_TYPE_KARIDNS_TINYDNS_WRAP   65406
#define DNS_TYPE_KARIDNS_ECS_TRUSTED    65407

#define EDNS_OPTION_KARIDNS_EXT         65153
#define EDNS_OPTION_EXPIRE              9     /* RFC 7314 */
/* 2: TYPE 65405 (tinydns location) carries the prefix length in bits + 4-octet network.
 * Peers with a different version fall back to a standard AXFR. */
#define KARIDNS_EXT_VERSION             2

// ECS / Location サブネットタグ構造体
typedef struct {
  char *cidr;       /* "8.8.8.0/24" のような文字列のまま保持 */
  cidr_entry_t parsed;
} ecs_cidr_entry_t;

typedef struct ecs_tag_def_s {
  char *tag;
  ecs_cidr_entry_t *cidrs;
  int cidr_count;
} ecs_tag_def_t;

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
    char tinydns_loc[2];        /* {0, 0} なら location制限なし */
    char *ecs_subnet_tag;       /* NULL = タグなし(常に表示)。arena確保文字列 */
    char *bind_location_tag;    /* NULL = タグなし(常に表示)。arena確保文字列 ($LOCATION用) */
    
    uint8_t *name_wire;         /* 事前構築オーナー名ワイヤー列 (NULL可) */
    uint16_t name_wire_len;
    
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
            uint8_t *mname_wire;
            uint16_t mname_wire_len;
            uint8_t *rname_wire;
            uint16_t rname_wire_len;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t minimum;
            uint8_t numbers_wire[20];
        } soa;
        struct {
            uint16_t pref;
            char *target;
            uint8_t *target_wire;
            uint16_t target_wire_len;
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
            uint8_t *target_wire;
            uint16_t target_wire_len;
        } srv;
        struct {
            uint8_t *wire_data;
            uint16_t wire_len;
        } txt; // TXT, SPF, AVC
        struct {
            uint8_t *wire_name;
            uint16_t wire_name_len;
        } name; // NS, PTR, CNAME, DNAME, MD, MF, MB, MG, MR, NSAP-PTR
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

// SIG(0) 鍵構造体 (RFC 2931 / RFC 3007)
typedef struct sig0_key {
    char *signer_name;    // Signer's Name (鍵の所有者名, e.g. "update.example.com.")
    uint8_t algorithm;     // DNSSEC Algorithm Number (8=RSASHA256, 13=ECDSAP256SHA256, 15=ED25519 等)
    uint16_t key_tag;      // KEY RRのキータグ(compute_sig0_keytagで計算 or 手動指定)
    EVP_PKEY *pkey;        // OpenSSL 秘密鍵オブジェクト
    int64_t fuzztime;      // テスト用時刻固定機構 (--break / 決定論テスト用)
} sig0_key_t;

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
    // 応答の OPT で通知する UDP ペイロードサイズ (udp-bufsize / zone-udp-bufsize)。
    // 0 なら既定の 1232。受信 OPT の解析では設定しない。
    uint16_t server_udp_size;
    
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

    // EDNS Client Subnet (ECS, RFC 7871)
    bool has_ecs;
    bool has_malformed_ecs;     // 受信: 形式が不正な ECS (RFC 7871 §6)。has_ecs は false のまま
    uint16_t ecs_family;
    uint8_t ecs_source_prefix;
    uint8_t ecs_scope_prefix;
    uint8_t ecs_addr[16];

    // KariDNS Extended AXFR (Option 65153)
    bool has_karidns_ext;
    uint8_t karidns_ext_version;
    uint32_t karidns_ext_hash;

    // EDNS EXPIRE (RFC 7314)
    bool has_expire_query;      // 受信: 長さ 0 の EXPIRE (§2 問い合わせ)
    bool has_expire_value;      // 受信: 長さ 4 の EXPIRE (§3 応答)
    uint32_t expire_value;
    bool send_expire;           // 送信: 応答の OPT に EXPIRE を付ける (受信値は反映しない)
    uint32_t send_expire_value;
} edns_info_t;

// ============================================================================
// 関数プロトタイプ
// ============================================================================

// 名前圧縮
void compress_ctx_init(compress_ctx_t *ctx);
void compress_ctx_init_packet(compress_ctx_t *ctx);
int compress_name(uint8_t *packet_buf, uint16_t *offset, const uint8_t *name, compress_ctx_t *ctx, size_t max_len);
void register_wire_name_for_compression(const uint8_t *packet_buf, uint16_t start_offset, compress_ctx_t *ctx);

// ワイヤーフォーマット名前操作
int skip_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset);
/* IXFR 要求 (RFC 1995 §3) の Authority にあるクライアントの SOA から SERIAL を取り出す。q_end は質問セクションの
 * 直後。Answer は読み飛ばす。最初の Authority RR が SOA で SERIAL まで読めれば true。TCP と UDP の IXFR で共有する。*/
bool ixfr_request_client_serial(const uint8_t *req, size_t req_len, size_t q_end, uint32_t *serial);
/* RFC 4648 §7 base32hex (upper case, no padding; RFC 5155 §3.3). */
void dns_base32hex_encode(const uint8_t *data, size_t len, char *out, size_t out_cap);
int expand_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, zone_arena_t *arena, char **name_out);

// レコード型変換・解析
const char *get_type_str(uint16_t type, zone_arena_t *arena);
int parse_resource_record(const uint8_t *packet, size_t packet_len, size_t *offset, zone_arena_t *arena, dns_record_t *rec, uint16_t *type_out);

// TSIG
bool tsig_algorithm_is_supported(const char *alg);
/* TSIG アルゴリズム名 (hmac-sha256 等) に対応する OpenSSL のダイジェスト。未対応なら NULL。
 * (EVP_MD は struct evp_md_st の typedef。ヘッダに openssl を持ち込まないためタグ名で宣言する) */
const struct evp_md_st *tsig_algorithm_evp_md(const char *alg);

/* Capsicum(cap_enter)突入前に呼ぶこと。TSIGで使う全HMACアルゴリズムを一度実行し、
 * OpenSSLの遅延初期化(openssl.cnfのopen等)をcapability mode突入前に完了させる。
 * cap_enter後に初回のHMAC()が走ると ECAPMODE -> SIGTRAP でプロセスが落ちる。
 * 全アルゴリズムのHMAC計算に成功した場合のみ true (FIPS環境でMD5が使えない場合等は false)。 */
bool tsig_prewarm_crypto(void);
int const_time_memcmp(const void *a, const void *b, size_t len);
int tsig_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len, tsig_key_t *key, uint16_t tsig_error,
                     uint8_t *prior_mac, size_t *prior_mac_len,
                     const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                     bool is_subsequent);
/* 署名する TSIG の Time Signed と Fudge。NULL なら現在時刻と 300。
 * BADTIME の応答はクライアントの値を使う (RFC 8945 §5.2.3)。 */
typedef struct {
    uint64_t time_signed;
    uint16_t fudge;
} tsig_sign_times_t;
int tsig_sign_packet_ex(uint8_t *packet, size_t *packet_len, size_t max_len, tsig_key_t *key, uint16_t tsig_error,
                        uint8_t *prior_mac, size_t *prior_mac_len,
                        const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                        bool is_subsequent, const tsig_sign_times_t *times);
/* key_name / alg で tsig_error の TSIG RR を付けたときに増えるバイト数 (MAC は alg の最大長)。
 * 名前が不正なら 0。 */
size_t tsig_rr_wire_size(const char *key_name, const char *alg, uint16_t tsig_error);
// 注意: mac_out は最低 EVP_MAX_MD_SIZE (64) バイトを確保すること。
// mac_len_out には実際にコピーされたバイト数（<= EVP_MAX_MD_SIZE）が返る。
int tsig_verify_packet(const uint8_t *packet, size_t packet_len, tsig_key_t *key,
                       const uint8_t *prior_mac, size_t prior_mac_len,
                       const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                       bool is_subsequent,
                       uint8_t *mac_out /* >= EVP_MAX_MD_SIZE bytes */,
                       size_t *mac_len_out);
/* tsig_verify_packet() の戻り値: TSIG が解釈できない (複数、最後の RR でない、RDATA の欠け、
 * MAC Size が範囲外)。RFC 8945 §5.2、§5.2.2.1 により FORMERR。 */
#define TSIG_VERIFY_FORMERR (-2)
/* tsig_verify_packet_ex() が返す、検証したメッセージの TSIG の値 */
typedef struct {
    uint64_t time_signed;
    uint16_t fudge;
    uint16_t error;       /* TSIG の Error */
    bool truncated;       /* MAC Size がハッシュ長より短い (RFC 8945 §5.2.2.1 で許される切り詰め) */
} tsig_verify_info_t;
/* 戻り値: 0 = 検証成功、-1 = TSIG がない、TSIG_VERIFY_FORMERR、
 * 17 = 鍵名またはアルゴリズムが key と違う (BADKEY)、16 = MAC 不一致 (BADSIG)、18 = 時刻範囲外 (BADTIME)。
 * 18 のときも mac_out に検証できた MAC を返す (BADTIME の応答の署名に使う。RFC 8945 §5.3.2)。
 * 応答の検証 (prior_mac を渡した最初のメッセージ) で、MAC Size 0 の無署名エラー (RFC 8945 §5.3.2)
 * なら TSIG の Error (16/17) を返す。 */
int tsig_verify_packet_ex(const uint8_t *packet, size_t packet_len, tsig_key_t *key,
                          const uint8_t *prior_mac, size_t prior_mac_len,
                          const uint8_t *unsigned_intermediate_msgs, size_t unsigned_intermediate_msgs_len,
                          bool is_subsequent,
                          uint8_t *mac_out /* >= EVP_MAX_MD_SIZE bytes */,
                          size_t *mac_len_out, tsig_verify_info_t *info);
/* TSIG が追加セクションの最後にただ 1 つあり、読めるときだけ true */
bool packet_has_tsig(const uint8_t *packet, size_t packet_len);

// SIG(0) & DNSKEY Tag
uint16_t compute_dnskey_tag(const uint8_t *rdata, size_t rdlen);
uint16_t compute_sig0_keytag(const sig0_key_t *key);
int sig0_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len, sig0_key_t *key);

// ============================================================================
// 名前の内部表現 (サーバー・karicheck 共通の正規テキスト形式)
//   ラベル中のオクテット '.' と '\' は "\." と "\\"、0x00-0x20 と 0x7F-0xFF は "\DDD"、
//   それ以外はそのまま。大文字小文字は保持し、絶対名は末尾にエスケープされない '.'、
//   ルートは "."。RFC 4343 §2.1 のエスケープ規則。この形では、DNS 名としての一致
//   (RFC 4343 §2: オクテット比較、ASCII 英字のみ大文字小文字を区別しない) が
//   文字列の strcasecmp の一致と同じになる (英字は必ずそのまま書かれるため)。
//   ゾーンパーサ、tinydns ローダー、クエリ名、XFR/UPDATE の受信名は全てこの形で作る。
// ============================================================================
// 255 オクテットの名前を全て \DDD で書いても収まる大きさ (RFC 1035 §2.3.4)
#define DNS_NAME_TEXT_SIZE 1025
// 1 ラベル (len オクテット) を正規形で out に書く。書いた文字数、入りきらなければ (size_t)-1。NUL は付けない。
size_t dns_label_to_text(const uint8_t *label, size_t len, char *out, size_t cap);
// 表示形式の名前 (\X, \DDD を含んでよい) を正規形にする。末尾ドットの有無は入力に従う。
// 戻り値は strlen(out)。不正なエスケープ、空ラベル、63 オクテット超のラベル、
// 255 オクテット超の名前 (RFC 1035 §2.3.4)、バッファ不足なら (size_t)-1。
size_t dns_name_normalize(const char *in, char *out, size_t cap);

/* メッセージ中の TSIG RR (RFC 8945 §4.2) */
typedef struct {
    size_t rr_offset;               /* TSIG RR の先頭。ここまでが TSIG を除いたメッセージ */
    size_t timers_offset;           /* Time Signed の位置 */
    char key_name[DNS_NAME_TEXT_SIZE];
    char alg_name[DNS_NAME_TEXT_SIZE];
    uint64_t time_signed;
    uint16_t fudge;
    uint16_t mac_size;
    const uint8_t *mac;
    uint16_t orig_id;
    uint16_t error;
    uint16_t other_len;
    const uint8_t *other;
} tsig_rr_t;
/* TSIG RR を探して読む。0 = TSIG なし、1 = 読めた、-1 = 解釈できない TSIG (複数ある、追加セクションの
 * 最後の RR でない、CLASS が ANY でない、RDATA が欠けている。RFC 8945 §5.2 で FORMERR)。 */
int tsig_parse_rr(const uint8_t *packet, size_t packet_len, tsig_rr_t *out);

/* 圧縮ポインタをたどって名前を正規形 (上記) で buf に書く。buf は DNS_NAME_TEXT_SIZE あれば足りる。 */
int expand_wire_name_to_buffer(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset,
                               char *buf, size_t buf_size);
int extract_wire_name_to_buffer(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, char *buf, size_t buf_size);
long write_uncompressed_name(uint8_t *buf, size_t offset, size_t max_len, const char *name);
// downcase=true なら RFC 4034 §6.2 の正規ワイヤ形式 (英字を小文字化)
long write_uncompressed_name_ext(uint8_t *buf, size_t offset, size_t max_len, const char *name, bool downcase);
int write_dns_name_str(uint8_t *packet_buf, uint16_t *offset, const char *name, compress_ctx_t *ctx, size_t max_len);
int serialize_dns_record(uint8_t *res, size_t max_res_len, uint16_t *offset_ptr, const dns_record_t *rec, compress_ctx_t *comp_ctx, const char *owner_name, uint32_t override_ttl);
/* RFC 4034 §6.2 item 3 (RFC 6840 §5.1) の型について、非圧縮の RDATA 内のドメイン名を小文字にする */
void dns_canonical_downcase_rdata(uint16_t type, uint8_t *rd, size_t len);
/* rec の RDATA を正規形 (非圧縮、上の型の名前は小文字) で buf に書き、長さを返す。書けなければ -1。
 * テキスト形式 (ゾーンファイル) とワイヤ形式 (転送、UPDATE) のレコードを同じ形で比べるのに使う。 */
long dns_record_canonical_rdata(const dns_record_t *rec, uint8_t *buf, size_t cap);
uint32_t parse_ttl_value(const char *ttl_str);

// EDNS
int parse_edns_opt(const uint8_t *req, size_t req_len,
                   uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount,
                   edns_info_t *edns);
void assemble_edns_opt(uint8_t *res, size_t max_res_len,
                       uint16_t *offset_inout, uint16_t *arcount_inout,
                       edns_info_t *edns, uint8_t rcode_ext, bool is_tcp,
                       struct server_config_s *cfg);
// assemble_edns_opt() が書く OPT RR のうち、EDE を除いた部分のバイト数の上限。
// 応答本文を組み立てる前に差し引いておくと、切り詰め (TC=1) 応答にも OPT が必ず入る
// (EDE は解決中に増えるので含めない。入りきらない場合は assemble_edns_opt() が EDE を省く)。
size_t edns_opt_reserve_len(const edns_info_t *edns, bool is_tcp, const struct server_config_s *cfg);
// msg (ヘッダの各カウントが有効な DNS メッセージ) の中から OPT RR を探す。
bool dns_find_opt_rr(const uint8_t *msg, size_t msg_len, size_t *opt_off, size_t *opt_len);
// 応答を質問セクションまで切り詰める (AN/NS/AR を落とす) が、OPT RR があれば
// 質問の直後へ移して残す (RFC 6891 §7)。TC ビットは呼び出し側で立てる。戻り値は新しい長さ。
size_t dns_truncate_keep_opt(uint8_t *res, size_t res_len, size_t q_end);

// 応答ヘッダの 3〜4 バイト目 (フラグと RCODE) を req から作る。ID と OPCODE、RD、CD は問い合わせから
// 引き継ぎ、QR=1、AA は引数どおり、TC/RA/Z/AD は 0 (RFC 1035 §4.1.1、RFC 4035 §3.1.6)。
// カウント (4〜11 バイト目) は変更しない。
void dns_init_response_header(uint8_t *res, const uint8_t *req, uint8_t rcode, bool aa);
// エラー応答の共通ビルダー。ヘッダは dns_init_response_header() (AA=0)、本文は要求の質問セクションを
// qd_keep 個だけ写し、それ以外 (回答・権威・追加、UPDATE の各セクション) は返さない。質問を区切れない、
// または入らないときは QDCOUNT=0。edns が OPT 付きの要求なら OPT (EDE を含む) を付ける (RFC 6891 §6.1.1、
// §7)。MQTYPE と EXPIRE は応答データに関するオプションなので付けない。edns=NULL なら OPT なし。
// 戻り値は応答の長さ (要求がヘッダより短い、または max_res_len < 12 なら 0)。
int dns_build_error_response(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len,
                             uint8_t rcode, uint8_t ext_rcode, uint16_t qd_keep,
                             edns_info_t *edns, bool is_tcp, struct server_config_s *cfg);
// OPT の VERSION がこのサーバーの実装 (0) を超える要求か (RFC 6891 §6.1.3)。
static inline bool edns_version_unsupported(const edns_info_t *edns) {
    return edns->present && edns->version > 0;
}
// その要求への BADVERS 応答 (OPT VERSION 0、質問を qd_keep 個写す)。クエリ経路と AXFR/IXFR の受付で共有する。
int dns_build_badvers_response(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len,
                               uint16_t qd_keep, edns_info_t *edns, bool is_tcp, struct server_config_s *cfg);

// UPDATE (RFC 2136) の処理結果。changed が false なら standby は active と同じ内容。
typedef struct {
    int prcount;
    int upcount;
    bool changed;       // ゾーンのデータが変わった
    bool soa_replaced;  // SOA が新しいシリアルの SOA で置き換わった (§3.4.2.2, §3.6)
} update_result_t;

int process_update_sections(const uint8_t *req, size_t req_len,
                             const char *zone_name,
                             zone_arena_t *standby,
                             update_result_t *out);

// ============================================================================
// Protocol Buffers Encoder (Minimal, Dependency-Free)
// ============================================================================
#define PB_WT_VARINT  0
#define PB_WT_FIXED64 1
#define PB_WT_LEN     2
#define PB_WT_FIXED32 5

size_t pb_encode_varint(uint8_t *out, size_t out_cap, uint64_t value);
size_t pb_encode_tag(uint8_t *out, size_t out_cap, uint32_t field_no, uint8_t wire_type);
size_t pb_encode_bytes_field(uint8_t *out, size_t out_cap, uint32_t field_no,
                              const uint8_t *data, size_t data_len);
size_t pb_encode_varint_field(uint8_t *out, size_t out_cap, uint32_t field_no, uint64_t value);
size_t pb_encode_fixed32_field(uint8_t *out, size_t out_cap, uint32_t field_no, uint32_t value);

// ============================================================================
// DNS Observatory Snapshot (POD for IPC transfer)
// ============================================================================
typedef struct {
    char domain[256];
    char view_name[64];
    bool is_secondary;
    uint32_t soa_serial;
    int slaves_configured;
    time_t last_notify_time;
    time_t last_transfer_time;
    uint64_t queries_total;
    uint64_t tcp_queries;
    uint64_t responses_noerror;
    uint64_t responses_nxdomain;
    uint64_t responses_nodata;
    uint64_t responses_servfail;
    uint64_t responses_refused;
    uint64_t edns_queries;
    uint64_t dnssec_do_queries;
    uint64_t ecs_queries;
    uint64_t rrl_dropped;
    uint64_t rrl_slipped;
    uint64_t notify_sent;
    uint64_t notify_ack;
    uint64_t axfr_success;
    uint64_t ixfr_success;
    uint64_t wirecache_hits;
    uint64_t wirecache_misses;
    bool wirecache_enabled;
    uint64_t wirecache_entries;
    uint64_t wirecache_bytes;
} zone_observatory_snapshot_t;

// 最初の質問 (UPDATE ではゾーンセクション) の名前に圧縮ポインタがあるか (X-15)。メッセージ最初の名前の
// ポインタは前に現れた名前を指せない (RFC 1035 §4.1.4) ので、そのような要求は FORMERR にする。
bool wire_question_name_compressed(const uint8_t *buf, size_t len);

// ============================================================================
// 高速クエリQuestion部パースヘルパー (UDP/TCP共通)
// 圧縮ポインタを含む名前は不正として false を返す (X-15)
// ============================================================================
bool parse_query_question_fast(const uint8_t *buf, size_t len, char *qname, size_t qname_size,
                               uint16_t *qtype, uint16_t *qclass, size_t *question_end);

#endif // DNS_WIRE_H
