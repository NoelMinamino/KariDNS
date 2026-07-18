#ifndef DNS_ZONE_PARSER_H
#define DNS_ZONE_PARSER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include "dns_wire.h"

typedef struct {
    const char *error_message;
    size_t error_offset;
    size_t token_length;
    const char *file_path; // 追加: このエラーがどのファイルで発生したか
} parse_error_t;

typedef struct parse_context_s {
    const char *base_dir;
    const char *default_origin;
    bool is_standalone_mode;
    parse_error_t *err_out;
    int current_depth;
    char* (*load_file_cb)(struct parse_context_s *ctx, const char *rel_path);
    void *user_data;

    // --- $INCLUDE 用に追加 ---
    char **shared_ttl_io;   // ★最重要: $TTLの書き戻し先。トップレベル呼び出し元が
                            //   自分のスタック変数のアドレスをセットし、以降の再帰
                            //   呼び出し全てで「同じポインタ」を使い回すこと。
    char **visited_paths;   // 祖先スタック(現在の呼び出しチェーンのみ、訪問済み集合ではない)
    int visited_count;      // スタックの現在の深さ
    int visited_cap;        // visited_paths配列の容量
} parse_context_t;

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
  char *file_paths[32];   // 追加: file_bufs[i] に対応する解決済み絶対パス
  int file_buf_count;
  int *hash_table;
  size_t hash_size;
  _Atomic int reader_count;
} zone_arena_t;

int parse_zone_fast(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx);
void zone_arena_init(zone_arena_t *arena);
void zone_arena_destroy(zone_arena_t *arena);
void zone_arena_free_include_buffers(zone_arena_t *arena);
void *arena_alloc(zone_arena_t *arena, size_t size);
char *arena_strdup(zone_arena_t *arena, const char *str);
void build_zone_index(zone_arena_t *arena);
bool compare_records(const dns_record_t *a, const dns_record_t *b, bool ignore_ttl);
bool record_exists_in_arena(zone_arena_t *arena, const dns_record_t *target);
uint32_t calc_fnv1a_str(const char *str);

#endif
