#ifndef DNS_ZONE_PARSER_H
#define DNS_ZONE_PARSER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>
#include "dns_wire.h"
#include "dns_utils.h"

typedef struct {
    const char *error_message;
    size_t error_offset;
    size_t token_length;
    const char *file_path; // 霑ｽ蜉: 縺薙・繧ｨ繝ｩ繝ｼ縺後←縺ｮ繝輔ぃ繧､繝ｫ縺ｧ逋ｺ逕溘＠縺溘°
} parse_error_t;

typedef struct parse_context_s {
    const char *base_dir;
    const char *default_origin;
    bool is_standalone_mode;
    parse_error_t *err_out;
    int current_depth;
    char* (*load_file_cb)(struct parse_context_s *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino);
    void *user_data;

    // --- $INCLUDE 逕ｨ縺ｫ霑ｽ蜉 ---
    char **shared_ttl_io;   // 笘・怙驥崎ｦ・ $TTL縺ｮ譖ｸ縺肴綾縺怜・縲ゅヨ繝・・繝ｬ繝吶Ν蜻ｼ縺ｳ蜃ｺ縺怜・縺・
                            //   閾ｪ蛻・・繧ｹ繧ｿ繝・け螟画焚縺ｮ繧｢繝峨Ξ繧ｹ繧偵そ繝・ヨ縺励∽ｻ･髯阪・蜀榊ｸｰ
                            //   蜻ｼ縺ｳ蜃ｺ縺怜・縺ｦ縺ｧ縲悟酔縺倥・繧､繝ｳ繧ｿ縲阪ｒ菴ｿ縺・屓縺吶％縺ｨ縲・
    char **shared_ecs_tag_io; // $ECS-SUBNET縺ｮ譖ｸ縺肴綾縺怜・ ($TTL縺ｮshared_ttl_io縺ｨ蜷後§謖吝虚)
    char **shared_loc_tag_io; // $LOCATION縺ｮ譖ｸ縺肴綾縺怜・ ($ECS-SUBNET縺ｮshared_ecs_tag_io縺ｨ蜷後§謖吝虚)
    char **visited_paths;   // 逾門・繧ｹ繧ｿ繝・け(迴ｾ蝨ｨ縺ｮ蜻ｼ縺ｳ蜃ｺ縺励メ繧ｧ繝ｼ繝ｳ縺ｮ縺ｿ縲∬ｨｪ蝠乗ｸ医∩髮・粋縺ｧ縺ｯ縺ｪ縺・
    dev_t *visited_devs;
    ino_t *visited_inos;
    int visited_count;      // 繧ｹ繧ｿ繝・け縺ｮ迴ｾ蝨ｨ縺ｮ豺ｱ縺・
    int visited_cap;        // visited_paths驟榊・縺ｮ螳ｹ驥・

    // --- 隍・焚繧ｾ繝ｼ繝ｳ繝ｻ隕ｪ蟄舌だ繝ｼ繝ｳ謖ｯ繧雁・縺醍畑 ---
    const char **all_zone_names;
    int all_zone_count;
    /* tinydns: 省略可。name (正規形) が同じ view のゾーンの頂点かを答える。あれば all_zone_names の
     * 代わりに使い、レコードごとの判定をゾーン数ではなくラベル数に比例させる。 */
    bool (*zone_exists)(const void *ud, const char *name);
    const void *zone_exists_ud;
    /* tinydns: all_zone_names のどのゾーンにも属さないため捨てたレコードの数と、
     * その最初のオーナー名 (arena 内の文字列)。all_zone_names が無ければ数えない。 */
    size_t out_of_zone_count;
    const char *first_out_of_zone;
    /* tinydns: SOA serial に使うデータファイルの mtime (0 = 不明、読み込み時刻を使う)。
     * パーサ自身はファイルを stat しない (X-13: サンドボックス内の再読み込みではパスを使えない)。 */
    time_t source_mtime;
} parse_context_t;

typedef struct {
    char code[2];
    uint8_t prefix[4];
    uint8_t prefix_bits; /* 0..32: CIDR prefix length in bits (prefix[] holds the masked network) */
} tinydns_location_entry_t;

/* S2 / S5 B-2: the sibling zones whose addresses a zone's Additional sections may use (additional-from-auth yes).
 * One malloc block (ids, targets and the target strings follow the struct). The zone data itself is read from the image;
 * this is the only mutable state kept next to it: zone_glue_refresh_dependents() (control thread, writer_lock) rewrites
 * ids[] and built_at after the zone was published. */
typedef struct zone_glue_s {
  uint64_t built_at;     /* the global publish counter when the siblings were looked up */
  int count;
  uint64_t *ids;         /* per target: id of the zone it resolved to in the view (0 = none / the zone itself) */
  const char **targets;  /* per target: name of an NS / MX / SRV target (first MAX_PRELINK_TARGETS distinct, in file order) */
} zone_glue_t;

/* RFC 5155 §3.1.7: one NSEC3 RR of a chain, keyed by the hashed owner name (the owner's first label, base32hex;
 * RFC 5155 §2 "hash order" = canonical order of the base32hex labels, compared case-insensitively). */
typedef struct {
  const char *hash;  /* first label of rec->name, not NUL-terminated */
  uint8_t hash_len;
  uint8_t algorithm;   /* chain parameters of rec (RDATA fields 0, 2, 3) */
  uint16_t iterations;
  const char *salt;
  dns_record_t *rec;
} nsec3_index_entry_t;

/* RFC 5155 §4 / §7.2: the NSEC3 RRs with the same hash algorithm, iterations and salt, sorted in hash order. */
typedef struct {
  uint8_t algorithm;
  uint16_t iterations;
  const char *salt;  /* RDATA text: hex digits, "" or "-" (no salt) */
  nsec3_index_entry_t *entries;
  size_t count;
} nsec3_chain_t;

/* R-31: the NSEC3 parameters the zone's denial proofs use, chosen once by build_zone_index() (RFC 5155 §4.1.2:
 * Flags 0 only; §7.3: one of several NSEC3PARAM RRs; §3.1.5: salt of 0-255 octets). param == NULL: no usable
 * NSEC3PARAM at the apex, i.e. the zone does not use NSEC3 for answers. */
typedef struct {
  const dns_record_t *param;  /* the chosen NSEC3PARAM RR (its owner is the apex) */
  const nsec3_chain_t *chain; /* its chain in the NSEC3 index, NULL if the zone has no NSEC3 RR for it */
  uint8_t algorithm;
  uint16_t iterations;
  uint8_t salt_len;
  uint8_t salt[255];
} nsec3_params_t;

typedef struct zone_arena_s {
  dns_record_t *records;
  size_t count;
  size_t records_cap;
  char **data_pools;      /* data_pool_cap 個 (必要に応じて倍に伸ばす、最大 ZONE_ARENA_MAX_POOLS) */
  int data_pool_count;
  int data_pool_cap;
  size_t first_pool_cap;  /* 0 = 64 KiB。小さいゾーンは読み込み前にファイルの大きさから決める */
  size_t current_pool_cap;
  size_t current_pool_idx;
  /* 読み込んだファイルの本文 (レコードの文字列はこの中を指す)。file_buf_cap 個まで (最大 32) */
  char **file_bufs;
  char **display_bufs;
  char **file_paths;      // file_bufs[i] に対応する解決済み絶対パス
  int file_buf_count;
  int file_buf_cap;
  int *hash_table;
  size_t hash_size;
  dns_record_t **nsec_records;
  size_t nsec_count;
  nsec3_chain_t *nsec3_chains;         /* built by build_zone_index(); entries point into nsec3_entries */
  size_t nsec3_chain_count;
  nsec3_index_entry_t *nsec3_entries;
  nsec3_params_t nsec3_active;         /* built by build_zone_index() */
  char **sorted_unique_names;
  size_t sorted_unique_count;
  bool is_tinydns_format; /* parse_tinydns_data()が呼ばれたzone_arenaでのみtrue */
  tinydns_location_entry_t *locations; /* NULL可 */
  int location_count;
  ecs_tag_def_t *bind_location_tags;      /* $LOCATION-TAG / AXFR復元用 */
  int bind_location_tag_count;
  ecs_tag_def_t *bind_ecs_tags;           /* $ECS-SUBNET-TAG / AXFR復元用 */
  int bind_ecs_tag_count;
  char **bind_ecs_trusted_resolvers;      /* AXFR(拡張モード)で受信した値、NULL可 */
  int bind_ecs_trusted_resolver_count;
  acl_entry_t *bind_ecs_trusted_resolvers_parsed;
  /* S2: グルーの対象名のうち、view で引くと自分以外のゾーン (または無し) になるもの。兄弟ゾーンの id か
   * 公開順が変わったら、このゾーンの応答 (兄弟のアドレスを含みうる) の版を上げる。NULL = 兄弟のアドレスを使わない。
   * 公開後は制御スレッドだけが書く (イメージには入れない)。S5 B-2 以降、公開した版の arena が持つのは
   * image / generation / rcache_ok / glue だけで、レコード・プール・索引・ゾーンファイルの本文は公開の前に解放する */
  zone_glue_t *glue;
  bool rcache_ok;          /* このゾーンの応答を共有の応答キャッシュに入れてよい */
  /* S5 phase B: 公開する版のコンパクトなイメージ (dns_zone_image.h)。応答を作る側はこれだけを読む。
   * zone_image_freeze() が公開の直前に作り、zone_arena_destroy() が解放する (1 回の malloc なので free()) */
  struct zone_image_s *image;
  /* 公開した版、および兄弟ゾーンが変わるたびに新しい値 (応答キャッシュの鍵)。0 = 未公開/テスト用 */
  _Atomic uint64_t generation;
} zone_arena_t;

#define ZONE_ARENA_MAX_POOLS 128
#define ZONE_ARENA_MAX_FILES 32
/* file を arena に登録する ($INCLUDE を含め最大 ZONE_ARENA_MAX_FILES)。失敗は -1 (呼び出し側が buf 等を解放) */
int zone_arena_add_file(zone_arena_t *arena, char *buf, char *display, char *path);
/* グルーを含めたゾーンのデータの版 (応答キャッシュの鍵) */
static inline uint64_t zone_arena_data_generation(const zone_arena_t *arena) {
  return atomic_load_explicit((_Atomic uint64_t *)&arena->generation, memory_order_acquire);
}

int parse_zone_fast(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx);
int parse_tinydns_data(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx);
dns_record_t *arena_alloc_record(zone_arena_t *arena, parse_context_t *ctx, const char *err_pos, const char *buf);
/* S5: rec->rdata[] を n 個ぶん arena に取る (rdata[i] への代入より前に呼ぶ)。失敗は false。rdata[] は 0 で埋める。rdata_count は呼び出し側が設定する */
bool arena_record_alloc_rdata(zone_arena_t *arena, dns_record_t *rec, int n);
void zone_arena_init(zone_arena_t *arena);
void zone_arena_destroy(zone_arena_t *arena);
/* S5 B-2: free the builder side of an arena once its image is made: records, data pools, indexes, zone level tables and
 * the kept zone file text. image, glue, rcache_ok and generation are kept. */
void zone_arena_free_builder(zone_arena_t *arena);
void zone_arena_free_include_buffers(zone_arena_t *arena);
/* 公開直前に呼ぶ: 応答キャッシュに入れてよいか (rcache_ok) を決める */
void build_zone_response_cache(zone_arena_t *arena, struct server_config_s *cfg, const char *view_name, const char *domain);
void *arena_alloc(zone_arena_t *arena, size_t size);
char *arena_strdup(zone_arena_t *arena, const char *str);
/* RFC 2181 s5.2 / RFC 4035 s2.2: harmonize_ttls=true normalizes RRset TTLs. */
void zone_arena_shrink_records(zone_arena_t *arena);
int build_zone_index(zone_arena_t *arena, bool harmonize_ttls);
/* Frees the lookup indexes build_zone_index() allocates besides the hash table (NSEC, NSEC3, sorted names). */
void zone_arena_free_sorted_indexes(zone_arena_t *arena);
/* RFC 5155 §3.2 / §4.2: algorithm, iterations and salt of an NSEC3 or NSEC3PARAM record (text RDATA fields 0, 2
 * and 3). false when the record has fewer fields or a number is out of range. */
bool nsec3_rdata_params(const dns_record_t *rec, uint8_t *algorithm, uint16_t *iterations, const char **salt);
/* The chain of `arena` with the parameters of the NSEC3PARAM (or NSEC3) record `param`, or NULL. */
const nsec3_chain_t *zone_find_nsec3_chain(const zone_arena_t *arena, const dns_record_t *param);
/* Hex text to octets without truncation: 0 for "", "-" or NULL; (size_t)-1 for an odd number of digits, a character
 * that is not a hex digit, or more than max_out octets. */
size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out);
/* RFC 1034 s4.2: drop records whose owner is not at or below apex (call before build_zone_index). */
size_t zone_arena_drop_out_of_zone(zone_arena_t *arena, const char *apex,
                                   void (*report)(const dns_record_t *rec, void *ud), void *ud);
/* X-32: drop records whose RDATA cannot be written in wire format (call before build_zone_index). */
size_t zone_arena_drop_unencodable(zone_arena_t *arena, void (*report)(const dns_record_t *rec, void *ud), void *ud);
bool compare_records(const dns_record_t *a, const dns_record_t *b, bool ignore_ttl);
bool record_exists_in_arena(zone_arena_t *arena, const dns_record_t *target);
uint32_t calc_fnv1a_str(const char *str);
uint32_t calc_fnv1a_strn(const char *str, size_t len);

#define FNV1A_WILDCARD_PREFIX_HASH 0x23de6ae9u

static inline uint32_t calc_fnv1a_continue(uint32_t hash, const char *str) {
    for (const char *p = str; *p; p++) {
        uint8_t c = (uint8_t)*p;
        if (c >= 'A' && c <= 'Z')
            c |= 0x20;
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}
/* name の末尾ドットを付け外しした形のハッシュ (レコード名と参照先の名前で末尾ドットの有無が
 * 違っても同じバケットを引くため)。末尾の '.' がエスケープされたもの ("a\.") はラベルの一部。
 * 一時バッファを使わない。 */
static inline uint32_t calc_fnv1a_other_root_form(const char *name) {
    size_t len = strlen(name);
    size_t bare = dns_name_len_no_root(name, len);
    return (bare != len) ? calc_fnv1a_strn(name, bare) : calc_fnv1a_continue(calc_fnv1a_str(name), ".");
}
int validate_zone_dname(zone_arena_t *arena, parse_error_t *err);
int validate_zone_name_lengths(zone_arena_t *arena, parse_error_t *err);
void free_ecs_tags_array(ecs_tag_def_t *tags, int count);
ecs_tag_def_t *clone_ecs_tags_array(const ecs_tag_def_t *src, int count);

#endif
