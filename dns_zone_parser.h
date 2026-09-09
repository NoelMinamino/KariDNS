#ifndef DNS_ZONE_PARSER_H
#define DNS_ZONE_PARSER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>
#include "dns_wire.h"

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
} parse_context_t;

typedef struct {
    char code[2];
    uint8_t prefix[4];
    uint8_t prefix_len; /* 0縲・ */
} tinydns_location_entry_t;

typedef struct {
  char *target_name;
  dns_record_t **records;
  int record_count;
} prelinked_glue_entry_t;

typedef struct zone_arena_s {
  dns_record_t *records;
  size_t count;
  size_t records_cap;
  char *data_pools[128];
  int data_pool_count;
  size_t current_pool_cap;
  size_t current_pool_idx;
  char *file_bufs[32];
  char *display_bufs[32];
  char *file_paths[32];   // 霑ｽ蜉: file_bufs[i] 縺ｫ蟇ｾ蠢懊☆繧玖ｧ｣豎ｺ貂医∩邨ｶ蟇ｾ繝代せ
  int file_buf_count;
  int *hash_table;
  size_t hash_size;
  dns_record_t **nsec_records;
  size_t nsec_count;
  char **sorted_unique_names;
  size_t sorted_unique_count;
  _Atomic int reader_count;
  bool is_tinydns_format; /* parse_tinydns_data()縺悟他縺ｰ繧後◆zone_arena縺ｧ縺ｮ縺ｿtrue */
  tinydns_location_entry_t *locations; /* NULL蜿ｯ */
  int location_count;
  ecs_tag_def_t *bind_location_tags;      /* 霑ｽ蜉: $LOCATION-TAG / AXFR蠕ｩ蜈・畑 */
  int bind_location_tag_count;
  ecs_tag_def_t *bind_ecs_tags;           /* 霑ｽ蜉: $ECS-SUBNET-TAG / AXFR蠕ｩ蜈・畑 */
  int bind_ecs_tag_count;
  char **bind_ecs_trusted_resolvers;      /* AXFR(諡｡蠑ｵ繝｢繝ｼ繝・縺ｧ蜿嶺ｿ｡縺励◆蛟､縲・ULL蜿ｯ */
  int bind_ecs_trusted_resolver_count;
  prelinked_glue_entry_t *prelinked_glue; /* 莠句燕繝ｪ繝ｳ繧ｯ縺輔ｌ縺蘗dditional繧ｰ繝ｫ繝ｼ */
  int prelinked_glue_count;
} zone_arena_t;

int parse_zone_fast(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx);
int parse_tinydns_data(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx);
dns_record_t *arena_alloc_record(zone_arena_t *arena, parse_context_t *ctx, const char *err_pos, const char *buf);
void zone_arena_init(zone_arena_t *arena);
void zone_arena_destroy(zone_arena_t *arena);
void zone_arena_free_include_buffers(zone_arena_t *arena);
void *arena_alloc(zone_arena_t *arena, size_t size);
char *arena_strdup(zone_arena_t *arena, const char *str);
/* RFC 2181 s5.2 / RFC 4035 s2.2: harmonize_ttls=true normalizes RRset TTLs. */
int build_zone_index(zone_arena_t *arena, bool harmonize_ttls);
bool compare_records(const dns_record_t *a, const dns_record_t *b, bool ignore_ttl);
bool record_exists_in_arena(zone_arena_t *arena, const dns_record_t *target);
uint32_t calc_fnv1a_str(const char *str);

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
int validate_zone_dname(zone_arena_t *arena, parse_error_t *err);
int validate_zone_name_lengths(zone_arena_t *arena, parse_error_t *err);
void free_ecs_tags_array(ecs_tag_def_t *tags, int count);
ecs_tag_def_t *clone_ecs_tags_array(const ecs_tag_def_t *src, int count);

#endif
