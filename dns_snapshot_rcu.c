#define OPENSSL_SUPPRESS_DEPRECATED 1
#define STATIC_TEST
#include "dns_snapshot_rcu.h"
#include "dns_dynamic_update.h"
#include "dns_server_internal.h"
#include "dns_catalog_zone.h"
#include "dns_edns_ecs.h"
#include "dns_axfr_ixfr.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_tsig_acl.h"
#include "dns_query_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

pthread_mutex_t g_zone_db_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

// Protected by g_zone_db_rebuild_lock
pending_coo_t *g_pending_coo = NULL;
int g_pending_coo_count = 0;
int g_pending_coo_capacity = 0;

_Atomic(zone_db_snapshot_t *) g_zone_db_active = ATOMIC_VAR_INIT(NULL);

zone_db_snapshot_t *acquire_zone_snapshot(void) {
  return atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
}

void retain_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap) {
    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
  }
}

/* worker_ctx_t を持たないスレッド用。load から参照獲得までを読み取り区間で守る。
 * 区間の外で load すると、retain する前に GC スレッドが epoch 待ちと
 * reader_count == 0 の確認を通り抜けて解放できてしまう。*/
zone_db_snapshot_t *acquire_retained_zone_snapshot(void) {
  rcu_aux_read_lock();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  retain_zone_snapshot(snap);
  rcu_aux_read_unlock();
  return snap;
}

void release_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap) {
    int old = atomic_load_explicit(&snap->reader_count, memory_order_relaxed);
    while (old > 0) {
      if (atomic_compare_exchange_weak_explicit(&snap->reader_count, &old, old - 1,
                                                memory_order_release, memory_order_relaxed)) {
        break;
      }
    }
  }
}

zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                        const char *view_name,
                                        const char *domain) {
  if (!cfg || !domain) return NULL;
  if (cfg->views) {
    for (view_config_t *v = cfg->views; v; v = v->next) {
      if (view_name && view_name[0] != '\0' && strcasecmp(v->name, view_name) != 0) continue;
      zone_config_t *z = view_find_zone_config(v, domain);
      if (z) return z;
      if (view_name && view_name[0] != '\0') return NULL;
    }
  } else {
    for (zone_config_t *z = cfg->zones; z; z = z->next) {
      if (domain_names_match_ci(z->domain, domain)) return z;
    }
  }
  return NULL;
}

// view 内で apex が domain と一致するゾーンを返す (最長一致ではなく完全一致)。
zone_db_entry_t *find_zone_exact_in_view(view_snapshot_t *view, const char *domain) {
  if (!view || !domain || !view->entries) return NULL;
  if (view->hash_size > 0 && view->hash_table && view->chain_next) {
    // エントリの domain は常に末尾ドット付き (create_new_zone_entry)。ハッシュも同じ形で計算する
    char fqdn[256];
    size_t dlen = strlen(domain);
    if (dlen > 0 && dns_name_len_no_root(domain, dlen) == dlen && dlen + 1 < sizeof(fqdn)) {
      memcpy(fqdn, domain, dlen);
      fqdn[dlen] = '.';
      fqdn[dlen + 1] = '\0';
      domain = fqdn;
    }
    uint32_t hash = calc_fnv1a_str(domain);
    size_t idx = hash & (view->hash_size - 1);
    for (int i = view->hash_table[idx]; i != -1; i = view->chain_next[i]) {
      if (i >= 0 && (size_t)i < view->zone_count && view->entries[i] &&
          domain_names_match_ci(view->entries[i]->domain, domain)) {
        return view->entries[i];
      }
    }
    return NULL;
  }
  for (size_t i = 0; i < view->zone_count; i++) {
    if (view->entries[i] && domain_names_match_ci(view->entries[i]->domain, domain)) {
      return view->entries[i];
    }
  }
  return NULL;
}

view_snapshot_t *snapshot_find_view(zone_db_snapshot_t *snap, const char *view_name) {
  if (!snap || !snap->views || !view_name) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    if (snap->views[v].name && strcasecmp(snap->views[v].name, view_name) == 0) {
      return &snap->views[v];
    }
  }
  return NULL;
}

// 同じゾーン名が複数の view にあり得るので、ゾーン単位の処理は必ず view を指定して引く (R-26)。
zone_db_entry_t *snapshot_get_zone_in_view(zone_db_snapshot_t *snap, const char *view_name,
                                           const char *domain) {
  return find_zone_exact_in_view(snapshot_find_view(snap, view_name), domain);
}

// domainに一致するゾーンを、view_nameが指定されていればそのview内だけを、
// NULLなら全view横断で検索する。戻り値は一致したview数(0/1/2以上)。
// 1件のみ一致した場合にresultへ結果を格納する。
int lookup_zone_across_views(zone_db_snapshot_t *snap, server_config_t *cfg,
                             const char *domain, const char *view_name,
                             zone_lookup_result_t *result) {
  if (!cfg || !domain || !result) return 0;
  int matches = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    if (view_name && v->name && strcasecmp(v->name, view_name) != 0) continue;
    zone_config_t *zcfg = view_find_zone_config(v, domain);
    if (!zcfg) continue;

    zone_db_entry_t *entry = v->name ? snapshot_get_zone_in_view(snap, v->name, domain) : NULL;
    matches++;
    if (matches == 1) {
      result->entry = entry;
      result->zcfg = zcfg;
      result->view_name = v->name;
    }
  }
  return matches;
}

// 全 view を横断して最初に一致したゾーンを返す。どの view のエントリかを区別できないため、
// サーバーのコードでは使わないこと (単体テスト用)。view ごとの処理は snapshot_get_zone_in_view()。
zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
  if (!snap || !domain || !snap->views) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    zone_db_entry_t *e = find_zone_exact_in_view(&snap->views[v], domain);
    if (e) return e;
  }
  return NULL;
}

/* サフィックス検索のキー長: 末尾のエスケープされない '.' を全て除いた長さ
 * (設定や呼び出し側の "example.com..." も "example.com" として扱ってきた挙動を保つ)。 */
static size_t zone_key_len(const char *name) {
  size_t len = strlen(name), bare;
  while ((bare = dns_name_len_no_root(name, len)) != len) len = bare;
  return len;
}

static zone_db_entry_t *view_suffix_hash_lookup(view_snapshot_t *view, const char *key, size_t key_len) {
  if (!view || !view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    return NULL;
  }
  uint32_t hash = calc_fnv1a_strn(key, key_len);
  size_t idx = hash & (view->suffix_hash_size - 1);
  for (int i = view->suffix_hash_table[idx]; i != -1; i = view->suffix_chain_next[i]) {
    zone_db_entry_t *entry = view->entries[i];
    if (!entry) continue;
    size_t z_len = zone_key_len(entry->domain);
    if (z_len == key_len && strncasecmp(entry->domain, key, key_len) == 0) {
      return entry;
    }
  }
  return NULL;
}

zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname) {
  if (!view || !qname) return NULL;
  if (!view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    // Suffix hash table not built (e.g. manually constructed mock view in fuzzers/tests)
    // Fall back to linear scan
    size_t q_len = zone_key_len(qname);
    zone_db_entry_t *best_entry = NULL;
    size_t longest_match_len = 0;
    for (size_t i = 0; i < view->zone_count; i++) {
      zone_db_entry_t *entry = view->entries[i];
      if (!entry) continue;
      size_t z_len = zone_key_len(entry->domain);
      // ラベル境界はエスケープされない '.' だけ (O-08)
      bool match = z_len == 0 ||
                   (q_len == z_len && strncasecmp(qname, entry->domain, z_len) == 0) ||
                   (q_len > z_len && qname[q_len - z_len - 1] == '.' &&
                    !dns_char_is_escaped(qname, q_len - z_len - 1) &&
                    strncasecmp(qname + (q_len - z_len), entry->domain, z_len) == 0);
      if (match && (!best_entry || z_len > longest_match_len)) {
        longest_match_len = z_len;
        best_entry = entry;
      }
    }
    return best_entry;
  }

  // O-08: ラベル境界はエスケープされない '.' だけ ("a\.example.test" は "example.test" の下ではない)。
  // 名前は正規形 (dns_wire.h) なので、ゾーン名とは大文字小文字を無視した文字列比較でよい。
  size_t q_len = zone_key_len(qname);

  const char *cursor = qname;
  size_t remaining = q_len;
  while (remaining > 0) {
    zone_db_entry_t *hit = view_suffix_hash_lookup(view, cursor, remaining);
    if (hit) return hit;
    // 次のラベル境界まで進める (末尾のルートの '.' は remaining の外)
    const char *dot = strchr_unescaped(cursor, '.');
    if (!dot || (size_t)(dot - cursor) >= remaining) break;
    remaining -= (size_t)(dot - cursor) + 1;
    cursor = dot + 1;
  }
  // ルートゾーン（"." または空文字列）へのフォールバック
  return view_suffix_hash_lookup(view, "", 0);
}

/* R-32: RFC 4035 §3.1.4.1 / §3.1.5: DS は委任点の親側にしか無い権威データで、子ゾーンは DS を持たない。
 * QTYPE DS の QNAME が見つかったゾーンの頂点そのものなら、親の名前 (最初のラベルを除いた名前、1 ラベルなら
 * ルート) で探し直し、あればそのゾーンから答える (DS、または親の SOA と NSEC/NSEC3 による NODATA。親がさらに
 * 上で委任していれば参照応答)。親を持たないとき、または親が forward ゾーン (権威データを持たない) のときは
 * 子の頂点から権威のある NODATA を返す (§3.1.4.1 がこの場合に定める応答)。QUERY 以外は qtype に 0 を渡す。 */
zone_db_entry_t *find_zone_for_query(view_snapshot_t *view, const char *qname, uint16_t qtype) {
  zone_db_entry_t *entry = find_zone_in_view(view, qname);
  if (qtype != 43 || !entry || !domain_names_match_ci(entry->domain, qname)) return entry;
  size_t q_len = zone_key_len(qname);
  if (q_len == 0) return entry; // ルート自身の DS は親を持たない
  const char *dot = strchr_unescaped(qname, '.');
  const char *parent = (dot && (size_t)(dot - qname) < q_len) ? dot + 1 : ".";
  zone_db_entry_t *p = find_zone_in_view(view, parent);
  if (!p || p == entry || p->kind == ZONE_KIND_FORWARD) return entry;
  return p;
}

zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name) {
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z) return NULL;
  atomic_init(&z->active_axfr, 0);
  atomic_init(&z->snapshot_refs, 1);
  z->id = zone_entry_next_id();

  size_t dlen = domain ? strlen(domain) : 0;
  if (dlen > 0 && dns_name_len_no_root(domain, dlen) == dlen && dlen + 1 < sizeof(z->domain)) {
    memcpy(z->domain, domain, dlen);
    z->domain[dlen] = '.';
    z->domain[dlen + 1] = '\0';
  } else {
    strncpy(z->domain, domain ? domain : "", sizeof(z->domain) - 1);
    z->domain[sizeof(z->domain) - 1] = '\0';
  }
  strncpy(z->view_name, view_name ? view_name : "", sizeof(z->view_name) - 1);
  z->view_name[sizeof(z->view_name) - 1] = '\0';
  pthread_mutex_init(&z->writer_lock, NULL);
  pthread_mutex_init(&z->ixfr_history.lock, NULL);
  atomic_init(&z->rcu.active, &zone_version_empty);
  return z;
}

void free_zone_db_entry(zone_db_entry_t *entry) {
  if (!entry) return;
  if (entry->groups) {
    for (int i = 0; i < entry->group_count; i++) {
      free(entry->groups[i]);
    }
    free(entry->groups);
  }
  wait_for_active_axfr(entry, 0);
  pthread_mutex_destroy(&entry->writer_lock);
  pthread_mutex_destroy(&entry->ixfr_history.lock);
  ixfr_history_clear(&entry->ixfr_history);
  zone_version_free(atomic_load_explicit(&entry->rcu.active, memory_order_relaxed));
  /* a DB zone's settings (the entry owns the current block; replaced ones go through zone_retire_object()) */
  free_zone_config((zone_config_t *)atomic_load_explicit(&entry->dbcfg, memory_order_relaxed));
  free(entry->catalog_master);
  free(entry->catalog_member_unique_id);
  free(entry->owning_catalog_domain);
  free(entry);
}

void free_zone_db_snapshot(zone_db_snapshot_t *snap) {
  if (!snap) return;
  if (snap->views) {
    for (size_t v = 0; v < snap->view_count; v++) {
      if (snap->views[v].entries) {
        for (size_t i = 0; i < snap->views[v].zone_count; i++) {
          zone_db_entry_t *entry = snap->views[v].entries[i];
          if (entry) {
            if (atomic_fetch_sub_explicit(&entry->snapshot_refs, 1, memory_order_acq_rel) == 1) {
              syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", entry->domain);
              free_zone_db_entry(entry);
            }
          }
        }
        free(snap->views[v].entries);
        snap->views[v].entries = NULL;
      }
      if (snap->views[v].name) {
        free(snap->views[v].name);
        snap->views[v].name = NULL;
      }
      if (snap->views[v].match_clients) {
        for (int i = 0; i < snap->views[v].match_clients_count; i++) {
          if (snap->views[v].match_clients[i]) free(snap->views[v].match_clients[i]);
        }
        free(snap->views[v].match_clients);
        snap->views[v].match_clients = NULL;
      }
      if (snap->views[v].match_clients_parsed) {
        free(snap->views[v].match_clients_parsed);
        snap->views[v].match_clients_parsed = NULL;
      }
      if (snap->views[v].hash_table) {
        free(snap->views[v].hash_table);
        snap->views[v].hash_table = NULL;
      }
      if (snap->views[v].chain_next) {
        free(snap->views[v].chain_next);
        snap->views[v].chain_next = NULL;
      }
      if (snap->views[v].suffix_hash_table) {
        free(snap->views[v].suffix_hash_table);
        snap->views[v].suffix_hash_table = NULL;
      }
      if (snap->views[v].suffix_chain_next) {
        free(snap->views[v].suffix_chain_next);
        snap->views[v].suffix_chain_next = NULL;
      }
    }
    free(snap->views);
    snap->views = NULL;
  }
  free(snap);
}

void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  if (!snap) return NULL;
  // タイムアウトしても解放しない (まだ読んでいるリーダーがいる)。待機関数が停滞を syslog に出す。
  while (!rcu_writer_wait_until_safe(snap->retire_epoch, 60000)) {
  }
  int retries = 0;
  useconds_t sleep_time = 1;
  while (atomic_load_explicit(&snap->reader_count, memory_order_acquire) > 0) {
    rcu_exponential_backoff(&retries, &sleep_time);
  }
  free_zone_db_snapshot(snap);
  return NULL;
}

static char *server_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
    int fd = open_via_dir_cache(rel_path, O_RDONLY | O_NOFOLLOW, 0, false);
    if (fd < 0) {
        return NULL;
    }
    
    if (out_dev || out_ino) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            close(fd);
            return NULL; // fstat failed, fail-closed
        }
    }

    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0 || len > KARIDNS_MAX_CONFIG_FILE_SIZE) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_len = fread(buf, 1, len, f);
    buf[read_len] = '\0';
    fclose(f);
    return buf;
}

#define MAX_PRELINK_TARGETS 256 /* the image's NAME_GLUE flag uses the same number (IMG_MAX_PRELINK_TARGETS) */

/* 公開の通し番号 (zone_publish が増やす)。兄弟ゾーンを調べた時点と、兄弟ゾーンの公開の前後を比べる */
static _Atomic uint64_t g_publish_counter;

/* グルーの対象名 (src の NS/MX/SRV の対象) について、view で引けるゾーンを調べる。自分以外の
 * ゾーン (または無し) になる名前を、そのゾーンの id (無ければ 0) とともに targets / ids に入れ、
 * 見つかった兄弟ゾーンに glue_provider の印を付ける。読み取り区間の中で呼ぶ。 */
static void glue_lookup_siblings(const char *zone_domain, view_snapshot_t *view, const char **targets,
                                 uint64_t *ids, int count) {
  for (int k = 0; k < count; k++) {
    zone_db_entry_t *s = view ? find_zone_in_view(view, targets[k]) : NULL;
    if (s && domain_names_match_ci(s->domain, zone_domain)) s = NULL;
    if (s) atomic_store_explicit(&s->glue_provider, true, memory_order_relaxed);
    ids[k] = s ? s->id : 0;
  }
}

/* 公開前の版 (zone_image_freeze() の後) に、兄弟ゾーンのグルーの追跡情報を作る。Additional のグルーの
 * 実体はイメージにある (自分のアドレスは NAME_GLUE の印、兄弟のアドレスは応答のたびに兄弟から引く:
 * append_glue_records の 3.)。ここで作るのは、NS/MX/SRV の対象名のうち兄弟ゾーンにありうるものと、そのとき引けた
 * 兄弟の id だけ (S2: 兄弟が変わったらこのゾーンの応答の版を上げる)。兄弟ゾーンを引くので、呼び出し側は
 * 読み取り区間に入れる。対象名は先頭の MAX_PRELINK_TARGETS 個 (ファイルの順、重複を除く) で、additional-from-auth yes
 * のときだけ追跡する。 */
void zone_glue_track_build(zone_version_t *ver, const char *zone_domain, view_snapshot_t *view,
                           additional_from_auth_t policy) {
  if (!ver) return;
  free(ver->glue);
  ver->glue = NULL;
  const zone_image_t *img = ver->image;
  if (!img || img->n_rrs == 0 || !zone_domain || policy != ADDITIONAL_AUTH_YES) return;

  char tmp[DNS_NAME_TEXT_SIZE];
  char *pool = NULL;
  size_t pool_len = 0, pool_cap = 0;
  uint32_t offs[MAX_PRELINK_TARGETS];
  int n = 0;
  for (uint32_t seq = 0; seq < img->n_rrs && n < MAX_PRELINK_TARGETS; seq++) {
    uint32_t k = zone_image_seq_rr(img, seq);
    uint16_t t = zone_image_rr_type(img, k);
    if (t != 2 && t != 15 && t != 33) continue;
    if (zone_image_rrs(img)[k].flags & ZONE_IMAGE_RR_RAW) continue; /* 生の RDATA に対象名の文字列は無い */
    if (zone_image_rr_target(img, k, tmp, sizeof(tmp)) != 0 || tmp[0] == '\0') continue;
    bool dup = false;
    for (int j = 0; j < n && !dup; j++) dup = domain_names_match_ci(pool + offs[j], tmp);
    if (dup) continue;
    size_t l = strlen(tmp) + 1;
    if (pool_len + l > pool_cap) {
      size_t nc = pool_cap ? pool_cap * 2 : 256;
      while (nc < pool_len + l) nc *= 2;
      char *np = realloc(pool, nc);
      if (!np) { free(pool); return; }
      pool = np;
      pool_cap = nc;
    }
    memcpy(pool + pool_len, tmp, l);
    offs[n++] = (uint32_t)pool_len;
    pool_len += l;
  }
  if (n > 0) {
    size_t head = (sizeof(zone_glue_t) + 7) & ~(size_t)7;
    zone_glue_t *g = malloc(head + (size_t)n * sizeof(uint64_t) + (size_t)n * sizeof(char *) + pool_len);
    if (g) {
      g->built_at = atomic_load_explicit(&g_publish_counter, memory_order_seq_cst);
      g->count = n;
      g->ids = (uint64_t *)(void *)((char *)g + head);
      g->targets = (const char **)(void *)(g->ids + n);
      char *strs = (char *)(g->targets + n);
      memcpy(strs, pool, pool_len);
      for (int k = 0; k < n; k++) g->targets[k] = strs + offs[k];
      glue_lookup_siblings(zone_domain, view, g->targets, g->ids, n);
      ver->glue = g;
    }
  }
  free(pool);
}

/* ---- S2: 解放待ちの版、公開、兄弟ゾーンの変更の反映 ----
 * S5 B-3: 公開した版は 1 つずつ malloc した zone_version_t で、書き込みは新しい版を作って公開する (standby の再利用は無い)。
 * 公開で退いた版は解放待ちに積み、猶予期間の後で制御スレッド (またはまとめて読み込む再構築) が解放する。
 * 積むのは複数のスレッド (制御、転送、UPDATE のワーカー) なので lock-free のスタックにし、
 * 取り出しはスタック全体を交換して行う。 */
typedef struct zone_retire_s {
  struct zone_retire_s *next;
  zone_db_entry_t *entry; /* 参照を 1 つ持つ */
  zone_version_t *ver;    /* 公開で退いた版。NULL なら obj / free_fn の項目 (zone_retire_object()) */
  void *obj;              /* ver が NULL のときに free_fn で解放する物 (ゾーン単位の設定など) */
  void (*free_fn)(void *);
  uint64_t epoch;
} zone_retire_t;

static _Atomic(zone_retire_t *) g_zone_retire_head;
static _Atomic uint64_t g_zone_entry_id;
static _Atomic bool g_glue_dirty;

uint64_t zone_entry_next_id(void) {
  return atomic_fetch_add_explicit(&g_zone_entry_id, 1, memory_order_relaxed) + 1;
}

static void zone_retire_push(zone_retire_t *r) {
  zone_retire_t *h = atomic_load_explicit(&g_zone_retire_head, memory_order_relaxed);
  do {
    r->next = h;
  } while (!atomic_compare_exchange_weak_explicit(&g_zone_retire_head, &h, r, memory_order_release,
                                                  memory_order_relaxed));
}

static void zone_entry_unref(zone_db_entry_t *e) {
  if (atomic_fetch_sub_explicit(&e->snapshot_refs, 1, memory_order_acq_rel) == 1) free_zone_db_entry(e);
}

/* 解放待ちを処理する。wait なら最も新しい世代まで猶予期間を待つ (再構築の途中でまとめて解放する)。
 * 読み取り区間の外から呼ぶこと。まだ解放できないもの (読み手、転送中、writer が使用中) は積み直す。 */
void zone_retire_process(bool wait) {
  zone_retire_t *list = atomic_exchange_explicit(&g_zone_retire_head, NULL, memory_order_acquire);
  if (!list) return;
  uint64_t max_epoch = 0;
  for (zone_retire_t *r = list; r; r = r->next) {
    if (r->epoch > max_epoch) max_epoch = r->epoch;
  }
  bool all_safe = wait ? rcu_writer_wait_until_safe(max_epoch, 60000) : rcu_writer_is_safe(max_epoch);
  while (list) {
    zone_retire_t *r = list;
    list = r->next;
    zone_db_entry_t *e = r->entry;
    if (!all_safe && !rcu_writer_is_safe(r->epoch)) {
      zone_retire_push(r);
      continue;
    }
    /* 送信中の AXFR と受信中の転送は、開始時の版を読み取り区間の外で使い続ける */
    if (atomic_load_explicit(&e->active_axfr, memory_order_acquire) > 0 ||
        atomic_load_explicit(&e->is_transferring, memory_order_acquire)) {
      zone_retire_push(r);
      continue;
    }
    if (r->ver)
      zone_version_free(r->ver);
    else
      r->free_fn(r->obj);
    zone_entry_unref(e);
    free(r);
  }
}

/* entry に属する物 obj を、世代 epoch の猶予期間が過ぎ、かつ entry が AXFR の送信中でも転送の受信中でもなくなってから
 * free_fn(obj) で解放する (退いた版と同じ解放待ちの積み方、同じ条件)。epoch は obj を読み手から外した公開 (rcu_writer_publish()) が
 * 返した世代。積むのは複数のスレッドから呼べる。成功すると entry の参照を 1 つ持ち、解放のときに手放す。
 * 戻り値 true なら以後の解放は zone_retire_process() が行う。false は積めなかった (メモリ不足) ことを示し、
 * obj は呼び出し側に残る (解放も参照も行っていない)。 */
bool zone_retire_object(zone_db_entry_t *entry, void *obj, void (*free_fn)(void *), uint64_t epoch) {
  if (!entry || !obj || !free_fn) return false;
  zone_retire_t *r = calloc(1, sizeof(*r));
  if (!r) return false;
  atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_relaxed);
  r->entry = entry;
  r->obj = obj;
  r->free_fn = free_fn;
  r->epoch = epoch;
  zone_retire_push(r);
  return true;
}

/* next を公開する。entry->writer_lock を持って呼ぶ (S2)。退いた版は解放待ちに積む (S5 B-3: 版は heap のものだけ。
 * 空の版とテストが自分で持つ版は積まない)。他のゾーンのグルーに使われているゾーン、または初めて公開するゾーン
 * なら、制御スレッドに依存するゾーンの応答の版の更新を頼む。 */
void zone_publish(zone_db_entry_t *entry, zone_version_t *next) {
  zone_version_t *old = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  bool first = atomic_load_explicit(&entry->publish_order, memory_order_relaxed) == 0;
  uint64_t epoch = rcu_writer_publish(&entry->rcu.active, next);
  atomic_store_explicit(&entry->publish_order,
                        atomic_fetch_add_explicit(&g_publish_counter, 1, memory_order_seq_cst) + 1,
                        memory_order_seq_cst);
  if (old != next && old->heap) {
    zone_retire_t *r = calloc(1, sizeof(*r));
    if (r) {
      atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_relaxed);
      r->entry = entry;
      r->ver = old;
      r->epoch = epoch;
      zone_retire_push(r);
    } else if (!atomic_load_explicit(&entry->active_axfr, memory_order_acquire) &&
               !atomic_load_explicit(&entry->is_transferring, memory_order_acquire) &&
               rcu_writer_wait_until_safe_in_reader(epoch, 60000)) {
      zone_version_free(old); /* 積めないときは、ここで猶予期間を待って解放する */
    } else {
      syslog(LOG_ERR, "[Zone] zone '%s': out of memory retiring the previous version; it is leaked", entry->domain);
    }
  }
  if (first || atomic_load_explicit(&entry->glue_provider, memory_order_relaxed))
    atomic_store_explicit(&g_glue_dirty, true, memory_order_release);
}

typedef struct {
  zone_db_entry_t *entry;
  view_snapshot_t *view;
} glue_todo_t;

/* 兄弟ゾーンが変わった (公開された、追加・削除された) ゾーンの応答の版を上げる。兄弟のアドレスは
 * 応答のたびに兄弟から引くので、データは作り直さない。共有の応答キャッシュに残る古い応答を引かせない
 * ためだけに版を上げ、兄弟の id と調べた時点を記録し直す (メモリは確保しない)。
 * 制御スレッドから (起動時はメインスレッドから)、読み取り区間の外で呼ぶ。glue->ids と
 * glue->built_at を公開後に書くのはこの関数だけ。force でなければ、グルーに関わる公開があったときだけ調べる。 */
void zone_glue_refresh_dependents(bool force) {
  if (!atomic_exchange_explicit(&g_glue_dirty, false, memory_order_acq_rel) && !force) return;
  zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
  if (!snap) return;
  glue_todo_t *todo = NULL;
  size_t n = 0, cap = 0;
  bool oom = false;
  for (size_t v = 0; v < snap->view_count && !oom; v++) {
    view_snapshot_t *view = &snap->views[v];
    rcu_aux_read_lock();
    for (size_t i = 0; i < view->zone_count; i++) {
      zone_db_entry_t *e = view->entries[i];
      if (!e) continue;
      zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
      zone_glue_t *g = a ? a->glue : NULL;
      if (!g) continue;
      bool need = false;
      for (int k = 0; k < g->count && !need; k++) {
        zone_db_entry_t *s = find_zone_in_view(view, g->targets[k]);
        if (s && domain_names_match_ci(s->domain, e->domain)) s = NULL;
        need = (s ? s->id : 0) != g->ids[k] ||
               (s && atomic_load_explicit(&s->publish_order, memory_order_seq_cst) > g->built_at);
      }
      if (!need) continue;
      if (n == cap) {
        size_t ncap = cap ? cap * 2 : 64;
        glue_todo_t *t = realloc(todo, ncap * sizeof(*t));
        if (!t) {
          oom = true;
          break;
        }
        todo = t;
        cap = ncap;
      }
      todo[n].entry = e;
      todo[n].view = view;
      n++;
    }
    rcu_aux_read_unlock();
  }
  if (oom) atomic_store_explicit(&g_glue_dirty, true, memory_order_release); /* 次の周期でやり直す */
  for (size_t i = 0; i < n; i++) {
    zone_db_entry_t *e = todo[i].entry;
    /* writer は公開の前に glue を作る。その途中の arena は active ではないが、公開と
     * 入れ違わないように writer_lock の下で active を読み直す */
    pthread_mutex_lock(&e->writer_lock);
    zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
    if (a && a->glue) {
      a->glue->built_at = atomic_load_explicit(&g_publish_counter, memory_order_seq_cst);
      rcu_aux_read_lock();
      glue_lookup_siblings(e->domain, todo[i].view, a->glue->targets, a->glue->ids, a->glue->count);
      rcu_aux_read_unlock();
      atomic_store_explicit(&a->generation, zone_data_generation_next(), memory_order_release);
    }
    pthread_mutex_unlock(&e->writer_lock);
  }
  free(todo);
  release_zone_snapshot(snap);
}

/* ゾーン外レコードのログ。1回の読み込みで出す行数を制限し、残りは件数だけにする。 */
#define OUT_OF_ZONE_LOG_MAX 10
typedef struct {
  const char *zone;
  size_t logged;
} out_of_zone_log_t;

static void log_out_of_zone_record(const dns_record_t *rec, void *ud) {
  out_of_zone_log_t *l = ud;
  if (l->logged >= OUT_OF_ZONE_LOG_MAX) return;
  l->logged++;
  syslog(LOG_WARNING, "[Zone] zone '%s': ignoring out-of-zone data '%s' %s", l->zone,
         rec->name ? rec->name : "", rec->type ? rec->type : "");
}

static void log_unencodable_record(const dns_record_t *rec, void *ud) {
  out_of_zone_log_t *l = ud;
  if (l->logged >= OUT_OF_ZONE_LOG_MAX) return;
  l->logged++;
  syslog(LOG_WARNING, "[Zone] zone '%s': ignoring record '%s' %s: its RDATA cannot be encoded "
         "(karicheck shows the reason)", l->zone, rec->name ? rec->name : "", rec->type ? rec->type : "");
}

/* X-32, S5 B-2: 書けないレコードを 1 件ずつ除き (警告は 1 回に OUT_OF_ZONE_LOG_MAX 行まで、残りは件数)、残りで続ける。
 * ゾーンファイルの読み込みも、AXFR/IXFR で受けたゾーンも、UPDATE を当てたゾーンも同じ扱い (公開するイメージには
 * serialize_dns_record() で書けないレコードを入れられない)。build_zone_index() の前に呼ぶ。除いた件数を返す。 */
size_t zone_drop_unencodable_logged(zone_arena_t *a, const char *zone, const char *from) {
  out_of_zone_log_t bad = { zone, 0 };
  size_t bad_count = zone_arena_drop_unencodable(a, log_unencodable_record, &bad);
  if (bad_count > 0)
    syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu record(s) that cannot be encoded from %s", zone, bad_count, from);
  return bad_count;
}

/* parse_context_t.zone_exists: name が view (ud) のゾーンの頂点か */
static bool view_has_zone(const void *ud, const char *name) {
  return view_find_zone_config((const view_config_t *)ud, name) != NULL;
}

reload_result_t reload_master_zone(zone_db_entry_t *entry, zone_config_t *zcfg) {
  if (!entry || !zcfg || !zcfg->file) return RELOAD_ERR_FILE_READ;
  const char *file = zcfg->file;
  struct stat root_st;
  char *buf = read_entire_file_stat(file, &root_st);
  dev_t root_dev = root_st.st_dev;
  ino_t root_ino = root_st.st_ino;
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return RELOAD_ERR_FILE_READ;
  }
  pthread_mutex_lock(&entry->writer_lock);
  if (!wait_for_active_axfr(entry, 5000)) {
    syslog(LOG_WARNING, "[Zone] Reload of zone '%s' postponed: active AXFR in progress (timeout 5s).", entry->domain);
    free(buf);
    pthread_mutex_unlock(&entry->writer_lock);
    return RELOAD_ERR_BUSY;
  }
  zone_version_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  /* S5 B-3: the zone is built in a builder of its own (freed on every way out) and published as a new version */
  zone_arena_t z_builder;
  zone_arena_t *z_standby = &z_builder;
  zone_arena_init(z_standby);
  /* R-21: 読み込み済みのゾーンの版が変わったら NOTIFY を送る (起動時の最初の読み込みでは送らない) */
  bool was_loaded = z_active->image && z_active->image->n_rrs > 0;
  uint32_t old_serial = entry->serial;

  /* S4: 小さいゾーンに 64 KiB の最初のプールを持たせない。プールの使用量 (レコードのワイヤー形式の
   * 前処理など) はゾーンファイルの 0.6-1.2 倍ほど。足りなければ半分の大きさで足す (arena_alloc) */
  size_t pool_cap = (size_t)root_st.st_size + 256;
  if (pool_cap < 1024) pool_cap = 1024;
  if (pool_cap > 64 * 1024) pool_cap = 64 * 1024;
  z_standby->first_pool_cap = pool_cap;
  char *root_file_path = strdup(file);
  if (!root_file_path || zone_arena_add_file(z_standby, buf, NULL, root_file_path) != 0) {
    free(root_file_path);
    free(buf);
    zone_arena_destroy(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Out of memory reloading zone '%s'", entry->domain);
    return RELOAD_ERR_PARSE;
  }

  char *root_ttl = NULL;
  char *root_ecs_tag = NULL;
  char *root_loc_tag = NULL;
  char *visited_paths[16];
  dev_t visited_devs[16];
  ino_t visited_inos[16];
  
  char abs_file[PATH_MAX];
  if (file[0] != '/' && g_startup_cwd[0] != '\0') {
      snprintf(abs_file, sizeof(abs_file), "%s/%s", g_startup_cwd, file);
  } else {
      snprintf(abs_file, sizeof(abs_file), "%s", file);
  }
  
  char *root_path = strdup(abs_file);

  parse_error_t parse_err = {0};
  parse_context_t ctx = {0};
  ctx.default_origin = entry->domain;
  ctx.base_dir = get_base_dir(root_path);
  if (!ctx.base_dir) {
      syslog(LOG_ERR, "[ZoneLoader] Out of memory allocating base_dir for zone '%s'", entry->domain);
      free(root_path);
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      return RELOAD_ERR_PARSE;
  }
  ctx.is_standalone_mode = false;
  ctx.load_file_cb = server_load_file_cb;
  ctx.shared_ttl_io = &root_ttl;
  ctx.shared_ecs_tag_io = &root_ecs_tag;
  ctx.shared_loc_tag_io = &root_loc_tag;
  ctx.visited_paths = visited_paths;
  ctx.visited_devs = visited_devs;
  ctx.visited_inos = visited_inos;
  ctx.visited_cap = 16;
  ctx.visited_count = 1;
  ctx.visited_paths[0] = root_path;
  ctx.visited_devs[0] = root_dev;
  ctx.visited_inos[0] = root_ino;
  ctx.err_out = &parse_err;
  ctx.source_mtime = root_st.st_mtime; // X-13: tinydns の SOA serial。パーサはパスを stat しない

  server_config_t *active_cfg = acquire_config_snapshot();
  // 親子ゾーンの振り分けに使うのは、このゾーンと同じ view のゾーンだけ (R-26)。
  // 別の view にしか無い子ゾーンの名前で、この view のレコードを落とさない。
  view_config_t *own_view = NULL;
  if (active_cfg) {
      for (view_config_t *v = active_cfg->views; v; v = v->next) {
          if (v->name && strcasecmp(v->name, entry->view_name) == 0) { own_view = v; break; }
      }
  }
  /* view の全ゾーン名の配列をゾーンごとに作ると、読み込み全体がゾーン数の 2 乗になる。
   * tinydns パーサには view の索引を引かせる (O-11 と同じく、view の全ゾーンが対象)。 */
  if (own_view) {
      ctx.zone_exists = view_has_zone;
      ctx.zone_exists_ud = own_view;
  }

  int count;
  if (zext(zcfg)->file_format && strcasecmp(zext(zcfg)->file_format, "tinydns") == 0) {
      count = parse_tinydns_data(buf, strlen(buf), z_standby, &ctx);
  } else {
      count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  }
  release_config_snapshot(active_cfg);
  free((void*)ctx.base_dir);
  free(root_path);

  if (count < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      if (parse_err.error_message) {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s': %s (offset=%zu, file=%s)",
                 entry->domain, file, parse_err.error_message,
                 parse_err.error_offset,
                 parse_err.file_path ? parse_err.file_path : file);
      } else {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s'", entry->domain, file);
      }
      return RELOAD_ERR_PARSE;
  }

  // R-27: ゾーン外のデータは読み込まない (BIND と同じく警告して無視する)
  out_of_zone_log_t ooz = { entry->domain, 0 };
  size_t ooz_count = zone_arena_drop_out_of_zone(z_standby, entry->domain, log_out_of_zone_record, &ooz);
  if (ooz_count > 0) {
      syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu out-of-zone record(s) from '%s'",
             entry->domain, ooz_count, file);
  }
  if (ctx.out_of_zone_count > 0) {
      syslog(LOG_WARNING, "[Zone] zone '%s': ignored %zu tinydns record(s) that belong to no configured zone "
             "in view '%s' (first: '%s') in '%s'", entry->domain, ctx.out_of_zone_count, entry->view_name,
             ctx.first_out_of_zone ? ctx.first_out_of_zone : "", file);
  }
  /* X-32: 書けないレコードはその 1 件だけ警告して除く (応答や AXFR で他のレコードを巻き込まない) */
  {
      char from[PATH_MAX + 8];
      snprintf(from, sizeof(from), "'%s'", file);
      zone_drop_unencodable_logged(z_standby, entry->domain, from);
  }

  zone_arena_shrink_records(z_standby);
  if (build_zone_index(z_standby, true) != 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_dname(z_standby, &parse_err) < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] DNAME validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_name_lengths(z_standby, &parse_err) < 0) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Name length validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  bool has_soa = false;
  uint32_t hash = calc_fnv1a_str(entry->domain);
  size_t idx = hash & (z_standby->hash_size - 1);
  for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
      if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
          has_soa = true;
          if (z_standby->records[i].rdata_count >= 7) {
              entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
              entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
              entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
              entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
          }
          break;
      }
  }
  if (!has_soa) {
      size_t elen = strlen(entry->domain);
      if (elen > 0 && dns_name_len_no_root(entry->domain, elen) == elen && elen + 2 < 256) {
          char dot_domain[256];
          memcpy(dot_domain, entry->domain, elen);
          dot_domain[elen] = '.';
          dot_domain[elen + 1] = '\0';
          uint32_t dot_hash = calc_fnv1a_str(dot_domain);
          size_t dot_idx = dot_hash & (z_standby->hash_size - 1);
          for (int i = z_standby->hash_table[dot_idx]; i != -1; i = z_standby->records[i].next_record) {
              if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
                  has_soa = true;
                  if (z_standby->records[i].rdata_count >= 7) {
                      entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
                      entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
                      entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
                      entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
                  }
                  break;
              }
          }
      }
  }
  if (!has_soa) {
      for (size_t i = 0; i < z_standby->count; i++) {
          if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
              has_soa = true;
              if (z_standby->records[i].rdata_count >= 7) {
                  entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
                  entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
                  entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
                  entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
              }
              break;
          }
      }
  }
  if (!has_soa) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Missing SOA reloading zone '%s' from '%s'", entry->domain, file);
      return RELOAD_ERR_MISSING_SOA;
  }

  /* S5 B-1: 応答を作る側が読むイメージ。公開の直前に 1 回だけ作る (クエリの経路では作らない) */
  z_standby->image = zone_image_freeze(z_standby, entry->domain);
  if (!z_standby->image) {
      zone_arena_destroy(z_standby);
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Failed to build the zone image after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }

  /* S5 B-2: 公開するのはイメージだけ。レコード・プール・索引・ゾーンファイルの本文はここで解放する。
   * S5 B-3: イメージは新しい版 (zone_version_t) に移る */
  zone_arena_free_builder(z_standby);
  zone_version_t *z_next = zone_version_new(z_standby);
  zone_arena_destroy(z_standby);
  if (!z_next) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Out of memory publishing the reloaded zone '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }

  // グルーの追跡は他ゾーンの active arena を読むので、読み取り区間で他の writer の再利用から守る
  rcu_aux_read_lock();
  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  server_config_t *active_cfg_prelink = acquire_config_snapshot();
  additional_from_auth_t policy = (zcfg && zext(zcfg)->additional_from_auth_specified)
                                      ? zext(zcfg)->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  zone_glue_track_build(z_next, entry->domain, snapshot_find_view(cur_snap, entry->view_name), policy);
  build_zone_response_cache(z_next, active_cfg_prelink, entry);
  release_config_snapshot(active_cfg_prelink);
  rcu_aux_read_unlock();

  compute_ixfr_diff(entry, z_active, z_next);
  zone_publish(entry, z_next);
  struct stat st_loaded;
  if (stat_via_dir_cache(file, &st_loaded) == 0) {
    entry->last_loaded_mtime = st_loaded.st_mtime;
    if (entry->is_secondary) {
      atomic_store_explicit(&entry->last_successful_transfer, (time_t)st_loaded.st_mtime, memory_order_release);
    }
  }
  pthread_mutex_unlock(&entry->writer_lock);
  syslog(LOG_NOTICE, "[Zone] Reload successful for '%s'", entry->domain);
  // RFC 1996 §4.5: プライマリのゾーンが変わったらセカンダリへ通知する
  if (was_loaded && !entry->is_secondary && entry->serial != old_serial) notify_request_send(entry);
  return RELOAD_OK;
}

STATIC_TEST void abort_rebuild_snapshot(zone_db_snapshot_t *new_snap, const char *reason) {
    syslog(LOG_ERR, "[Core] Memory allocation failed during snapshot rebuild (%s), aborting", reason);
    if (new_snap) {
        free_zone_db_snapshot(new_snap);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

/* R-28, RFC 9432 §5.4: カタログメンバーの同一性は (メンバーゾーン名, メンバーノードのラベル) だけで決まる。
 * group (§4.3.2) は設定の選び分けにしか使わないので比較に含めない。ht/chain/hsize は
 * calc_catalog_member_hash() で作ったハッシュ表 (作れなかったときは NULL で線形探索)。 */
static int catalog_member_index(const catalog_member_id_t *list, int count, const int *ht, const int *chain,
                                size_t hsize, const char *domain, const char *unique_id) {
    if (ht && chain) {
        size_t idx = calc_catalog_member_hash(domain, unique_id) & (hsize - 1);
        for (int j = ht[idx]; j != -1; j = chain[j]) {
            if (strcasecmp(domain, list[j].domain) == 0 && strcmp(unique_id, list[j].unique_id) == 0) return j;
        }
        return -1;
    }
    for (int j = 0; j < count; j++) {
        if (strcasecmp(domain, list[j].domain) == 0 && strcmp(unique_id, list[j].unique_id) == 0) return j;
    }
    return -1;
}

/* catalog_member_index() 用のハッシュ表を作る。作れなければ *ht / *chain は NULL のまま
 * (catalog_member_index() は線形探索になる)。呼び出し側が free() する。 */
static void catalog_member_hash_build(const catalog_member_id_t *list, int count,
                                      int **ht, int **chain, size_t *hsize) {
    *ht = NULL;
    *chain = NULL;
    *hsize = 0;
    if (!list || count <= 0) return;
    size_t p = 256;
    while (p < (size_t)count * 2) p <<= 1;
    int *t = malloc(p * sizeof(int));
    int *c = malloc((size_t)count * sizeof(int));
    if (!t || !c) {
        free(t);
        free(c);
        return;
    }
    for (size_t k = 0; k < p; k++) t[k] = -1;
    for (int j = 0; j < count; j++) {
        size_t idx = calc_catalog_member_hash(list[j].domain, list[j].unique_id) & (p - 1);
        c[j] = t[idx];
        t[idx] = j;
    }
    *ht = t;
    *chain = c;
    *hsize = p;
}

static bool catalog_groups_equal(const catalog_member_id_t *a, const catalog_member_id_t *b) {
    if (a->group_count != b->group_count) return false;
    for (int k = 0; k < a->group_count; k++) {
        if (strcmp(a->groups[k], b->groups[k]) != 0) return false;
    }
    return true;
}

/* メンバーのゾーンエントリの group をその場で置き換える (エントリと転送の状態はそのまま)。
 * entry->groups を読むのは解放だけで、書き手はスナップショットを作り直すこのスレッドだけ。 */
static void catalog_entry_set_groups(zone_db_entry_t *entry, const catalog_member_id_t *m) {
    if (entry->groups) {
        for (int g = 0; g < entry->group_count; g++) free(entry->groups[g]);
        free(entry->groups);
        entry->groups = NULL;
    }
    entry->group_count = 0;
    if (m->group_count <= 0) return;
    entry->groups = calloc(m->group_count, sizeof(char *));
    if (!entry->groups) return;
    for (int g = 0; g < m->group_count; g++) {
        entry->groups[g] = strdup(m->groups[g]);
        if (!entry->groups[g]) break;
        entry->group_count = g + 1;
    }
}

/* Both hash tables of a view (zone name, and the suffix table find_zone_in_view() walks) from vs->entries /
 * vs->zone_count.  false: out of memory (the view keeps what was allocated; free_zone_db_snapshot() frees it). */
static bool view_build_hashes(view_snapshot_t *vs) {
    size_t p = 256;
    while (p < vs->zone_count * 2) p <<= 1;
    vs->hash_size = p;
    if (vs->hash_size > 0) {
        vs->hash_table = malloc(vs->hash_size * sizeof(int));
        if (vs->hash_table) {
            for (size_t i = 0; i < vs->hash_size; i++) vs->hash_table[i] = -1;
        }
    }
    if (vs->zone_count > 0) {
        vs->chain_next = malloc(vs->zone_count * sizeof(int));
        if (vs->chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) vs->chain_next[i] = -1;
        }
    }

    vs->suffix_hash_size = p;
    if (vs->suffix_hash_size > 0) {
        vs->suffix_hash_table = malloc(vs->suffix_hash_size * sizeof(int));
        if (vs->suffix_hash_table) {
            for (size_t i = 0; i < vs->suffix_hash_size; i++) vs->suffix_hash_table[i] = -1;
        }
    }
    if (vs->zone_count > 0) {
        vs->suffix_chain_next = malloc(vs->zone_count * sizeof(int));
        if (vs->suffix_chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) vs->suffix_chain_next[i] = -1;
        }
    }

    if ((vs->hash_size > 0 && !vs->hash_table) || (vs->zone_count > 0 && !vs->chain_next) ||
        (vs->suffix_hash_size > 0 && !vs->suffix_hash_table) || (vs->zone_count > 0 && !vs->suffix_chain_next)) {
        return false;
    }

    if (vs->hash_table && vs->chain_next) {
        for (size_t i = 0; i < vs->zone_count; i++) {
            if (!vs->entries[i]) continue;
            uint32_t hash = calc_fnv1a_str(vs->entries[i]->domain);
            size_t idx = hash & (vs->hash_size - 1);
            vs->chain_next[i] = vs->hash_table[idx];
            vs->hash_table[idx] = i;
        }
    }

    if (vs->suffix_hash_table && vs->suffix_chain_next) {
        for (size_t i = 0; i < vs->zone_count; i++) {
            if (!vs->entries[i]) continue;
            size_t z_len = zone_key_len(vs->entries[i]->domain);
            uint32_t hash = calc_fnv1a_strn(vs->entries[i]->domain, z_len);
            size_t idx = hash & (vs->suffix_hash_size - 1);
            vs->suffix_chain_next[i] = vs->suffix_hash_table[idx];
            vs->suffix_hash_table[idx] = i;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* DB zone registry and view delta (beta design 4.2, 4.4, 4.5)                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
    char name[KARIDNS_VIEW_NAME_MAX];
    dbreg_zone_t **tab;                 /* hash chains by dns_name_hash_ci(), nb is a power of two */
    size_t nb, count;
    zone_db_entry_t **adds;             /* entries that should enter the view snapshot (a reference each) */
    size_t n_adds, cap_adds;
    zone_db_entry_t **removes;          /* entries that should leave it (a reference each) */
    size_t n_removes, cap_removes;
} dbreg_view_t;

/* all of it is protected by g_zone_db_rebuild_lock */
static dbreg_view_t *g_dbreg_views;
static size_t g_dbreg_nviews, g_dbreg_capviews, g_dbreg_hint;
static _Atomic size_t g_dbreg_pending;

static void dbreg_entry_ref(zone_db_entry_t *e) {
    atomic_fetch_add_explicit(&e->snapshot_refs, 1, memory_order_release);
}

static dbreg_view_t *dbreg_view_get(const char *name, bool create) {
    size_t n = g_dbreg_nviews;
    if (n && g_dbreg_hint < n && strcasecmp(g_dbreg_views[g_dbreg_hint].name, name) == 0)
        return &g_dbreg_views[g_dbreg_hint];
    for (size_t i = 0; i < n; i++) {
        if (strcasecmp(g_dbreg_views[i].name, name) == 0) {
            g_dbreg_hint = i;
            return &g_dbreg_views[i];
        }
    }
    if (!create) return NULL;
    if (n == g_dbreg_capviews) {
        size_t nc = n ? n * 2 : 4;
        dbreg_view_t *nv = realloc(g_dbreg_views, nc * sizeof(*nv));
        if (!nv) return NULL;
        g_dbreg_views = nv;
        g_dbreg_capviews = nc;
    }
    dbreg_view_t *v = &g_dbreg_views[n];
    memset(v, 0, sizeof(*v));
    snprintf(v->name, sizeof(v->name), "%s", name);
    g_dbreg_nviews = n + 1;
    g_dbreg_hint = n;
    return v;
}

static dbreg_zone_t *dbreg_find(const dbreg_view_t *rv, const char *name, uint32_t h) {
    if (!rv->nb) return NULL;
    for (dbreg_zone_t *z = rv->tab[h & (rv->nb - 1)]; z; z = z->next) {
        if (z->hash == h && domain_names_match_ci(z->name, name)) return z;
    }
    return NULL;
}

static dbreg_zone_t *dbreg_add(dbreg_view_t *rv, const char *name, uint32_t h) {
    if (rv->count >= rv->nb) {
        size_t nnb = rv->nb ? rv->nb * 2 : 64;
        dbreg_zone_t **nt = calloc(nnb, sizeof(*nt));
        if (!nt) return NULL;
        for (size_t i = 0; i < rv->nb; i++) {
            dbreg_zone_t *z = rv->tab[i];
            while (z) {
                dbreg_zone_t *nx = z->next;
                size_t b = z->hash & (nnb - 1);
                z->next = nt[b];
                nt[b] = z;
                z = nx;
            }
        }
        free(rv->tab);
        rv->tab = nt;
        rv->nb = nnb;
    }
    size_t l = strlen(name);
    dbreg_zone_t *z = calloc(1, sizeof(*z) + l + 1);
    if (!z) return NULL;
    memcpy(z->name, name, l + 1);
    z->hash = h;
    size_t b = h & (rv->nb - 1);
    z->next = rv->tab[b];
    rv->tab[b] = z;
    rv->count++;
    return z;
}

static void dbreg_unlink(dbreg_view_t *rv, dbreg_zone_t *z) {
    dbreg_zone_t **pp = &rv->tab[z->hash & (rv->nb - 1)];
    while (*pp && *pp != z) pp = &(*pp)->next;
    if (*pp) *pp = z->next;
    rv->count--;
}

static bool dbreg_queue_reserve(zone_db_entry_t ***arr, size_t n, size_t *cap) {
    if (n < *cap) return true;
    size_t nc = *cap ? *cap * 2 : 16;
    zone_db_entry_t **na = realloc(*arr, nc * sizeof(**arr));
    if (!na) return false;
    *arr = na;
    *cap = nc;
    return true;
}

/* does a zone of the configuration hide a DB zone of this name in this view? (D-PRIO: file, program, forward and
 * secondary zones all come from zone {} statements) */
static bool dbreg_config_shadows(const char *view, const char *name) {
    rcu_aux_read_lock();
    server_config_t *cfg = acquire_config_snapshot();
    bool sh = cfg && find_zone_config_in_view(cfg, view, name) != NULL;
    release_config_snapshot(cfg);
    rcu_aux_read_unlock();
    return sh;
}

static void dbreg_set_error(dbreg_zone_t *z, const char *reason) {
    free(z->error);
    z->error = reason ? strdup(reason) : NULL;
}

int dbreg_commit(const char *view, const char *name, zone_db_entry_t *entry, bool created, int64_t source_id,
                 uint32_t serial, const uint8_t digest[32], bool *shadowed) {
    bool sh = dbreg_config_shadows(view, name);
    int rc = -1;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, true);
    if (!rv) goto out;
    uint32_t h = dns_name_hash_ci(name);
    dbreg_zone_t *z = dbreg_find(rv, name, h);
    bool fresh = false;
    if (!z) {
        if (!(z = dbreg_add(rv, name, h))) goto out;
        fresh = true;
    }
    bool queue_add = created && !sh;
    bool queue_remove = created && z->entry && z->entry != entry;
    if ((queue_add && !dbreg_queue_reserve(&rv->adds, rv->n_adds, &rv->cap_adds)) ||
        (queue_remove && !dbreg_queue_reserve(&rv->removes, rv->n_removes, &rv->cap_removes))) {
        if (fresh) {
            dbreg_unlink(rv, z);
            free(z);
        }
        goto out;
    }
    if (created) {
        if (queue_remove) {                            /* a new entry replaces one registered earlier: that one leaves */
            rv->removes[rv->n_removes++] = z->entry;   /* (the registry's reference moves to the queue) */
            atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
        }
        z->entry = entry;                              /* the initial reference of the entry is the registry's */
        if (queue_add) {
            dbreg_entry_ref(entry);
            rv->adds[rv->n_adds++] = entry;
            atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
        }
    }
    z->source_id = source_id;
    z->serial = serial;
    memcpy(z->digest, digest, 32);
    z->last_result = DBREG_APPLIED;
    z->shadowed = sh;
    dbreg_set_error(z, NULL);
    rc = 0;
out:
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (shadowed) *shadowed = sh;
    return rc;
}

zone_db_entry_t *dbreg_lookup_entry(const char *view, const char *name) {
    zone_db_entry_t *e = NULL;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    if (rv) {
        dbreg_zone_t *z = dbreg_find(rv, name, dns_name_hash_ci(name));
        if (z) e = z->entry;
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return e;
}

bool dbreg_reject(const char *view, const char *name, int64_t source_id, const char *reason) {
    bool ok = false;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, true);
    if (rv) {
        uint32_t h = dns_name_hash_ci(name);
        dbreg_zone_t *z = dbreg_find(rv, name, h);
        if (!z) z = dbreg_add(rv, name, h);
        if (z) {
            if (!z->entry) z->source_id = source_id;
            z->last_result = DBREG_REJECTED;
            dbreg_set_error(z, reason);
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return ok;
}

int dbreg_delete(const char *view, const char *name, int64_t source_id) {
    int rc = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_view_t *rv = dbreg_view_get(view, false);
    dbreg_zone_t *z = rv ? dbreg_find(rv, name, dns_name_hash_ci(name)) : NULL;
    if (z && z->source_id == source_id) {
        zone_db_entry_t *e = z->entry;
        bool in_snap = false;
        if (e) {
            /* the active snapshot cannot change or be freed while we hold the lock (only lock holders replace it) */
            zone_db_snapshot_t *snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
            in_snap = find_zone_exact_in_view(snapshot_find_view(snap, view), e->domain) == e;
        }
        if (in_snap && !dbreg_queue_reserve(&rv->removes, rv->n_removes, &rv->cap_removes)) {
            rc = -1;
        } else {
            dbreg_unlink(rv, z);
            if (in_snap) {
                rv->removes[rv->n_removes++] = e;      /* the registry's reference moves to the queue */
                atomic_fetch_add_explicit(&g_dbreg_pending, 1, memory_order_relaxed);
            } else if (e) {
                zone_entry_unref(e);
            }
            free(z->error);
            free(z);
            rc = 1;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return rc;
}

size_t dbreg_pending_count(void) {
    return atomic_load_explicit(&g_dbreg_pending, memory_order_relaxed);
}

/* drop the queued additions and removals (with their references); the lock is held */
static void dbreg_pending_drop_locked(void) {
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        dbreg_view_t *rv = &g_dbreg_views[v];
        for (size_t i = 0; i < rv->n_adds; i++) zone_entry_unref(rv->adds[i]);
        for (size_t i = 0; i < rv->n_removes; i++) zone_entry_unref(rv->removes[i]);
        rv->n_adds = rv->n_removes = 0;
    }
    atomic_store_explicit(&g_dbreg_pending, 0, memory_order_relaxed);
}

/* The registry's entries of one view that the new configuration does not hide (beta design 4.5); the lock is held.
 * vc: the view of the new configuration, old_view: the same view of the snapshot being replaced (a catalog member of
 * the same name hides a DB zone too).  *out: a malloc'ed array of the entries (no references taken).  Updates the
 * shadowed flags and logs the changes.  (size_t)-1: out of memory. */
static size_t dbreg_collect_view_locked(const view_config_t *vc, view_snapshot_t *old_view, zone_db_entry_t ***out) {
    *out = NULL;
    dbreg_view_t *rv = vc->name ? dbreg_view_get(vc->name, false) : NULL;
    if (!rv || rv->count == 0) return 0;
    zone_db_entry_t **list = malloc(rv->count * sizeof(*list));
    if (!list) return (size_t)-1;
    size_t n = 0;
    for (size_t b = 0; b < rv->nb; b++) {
        for (dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
            if (!z->entry) continue;
            bool sh = view_find_zone_config(vc, z->name) != NULL;
            if (!sh && old_view) {
                zone_db_entry_t *o = find_zone_exact_in_view(old_view, z->name);
                sh = o && o != z->entry && o->is_catalog_member;
            }
            if (sh && !z->shadowed)
                syslog(LOG_WARNING, "[DB] zone %s from the DB is shadowed by the zone in karidns.conf (view '%s')",
                       z->name, vc->name);
            else if (!sh && z->shadowed)
                syslog(LOG_NOTICE, "[DB] zone %s (view '%s') is served from the DB again: the zone in karidns.conf "
                       "is gone", z->name, vc->name);
            z->shadowed = sh;
            if (!sh) list[n++] = z->entry;
        }
    }
    *out = list;
    return n;
}

static int cmp_ptr(const void *a, const void *b) {
    const void *x = *(const void *const *)a, *y = *(const void *const *)b;
    return x < y ? -1 : x > y;
}

static bool ptr_in_sorted(zone_db_entry_t *const *arr, size_t n, const zone_db_entry_t *p) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (arr[mid] == p) return true;
        if (arr[mid] < p) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

int snapshot_apply_db_delta(void) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    if (atomic_load_explicit(&g_dbreg_pending, memory_order_relaxed) == 0) {
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        return 0;
    }
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (!old_snap) {                              /* no snapshot yet: the first full rebuild reads the registry */
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        return 0;
    }
    zone_db_snapshot_t *ns = calloc(1, sizeof(*ns));
    if (ns && old_snap->view_count) ns->views = calloc(old_snap->view_count, sizeof(view_snapshot_t));
    if (!ns || (old_snap->view_count && !ns->views)) {
        free(ns);
        pthread_mutex_unlock(&g_zone_db_rebuild_lock);
        syslog(LOG_ERR, "[DB] out of memory publishing the zone changes; they are kept for the next try");
        return -1;
    }
    ns->view_count = old_snap->view_count;
    atomic_init(&ns->reader_count, 0);
    int changes = 0;
    for (size_t v = 0; v < old_snap->view_count; v++) {
        view_snapshot_t *ov = &old_snap->views[v];
        view_snapshot_t *vs = &ns->views[v];
        vs->name = strdup(ov->name ? ov->name : "");
        bool ok = vs->name != NULL;
        vs->match_clients_count = ov->match_clients_count;
        if (ok && ov->match_clients_count > 0) {
            vs->match_clients = calloc(ov->match_clients_count, sizeof(char *));
            ok = vs->match_clients != NULL;
            for (int i = 0; ok && i < ov->match_clients_count; i++) {
                if (ov->match_clients[i]) ok = (vs->match_clients[i] = strdup(ov->match_clients[i])) != NULL;
            }
            if (ok) vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
        }
        dbreg_view_t *rv = ok ? dbreg_view_get(vs->name, false) : NULL;
        /* removals that are in this view, and additions that are still wanted and not in it yet */
        size_t nrem = 0, nadd = 0;
        zone_db_entry_t **rem = NULL, **add = NULL;
        if (rv && (rv->n_removes || rv->n_adds)) {
            rem = malloc((rv->n_removes + 1) * sizeof(*rem));
            add = malloc((rv->n_adds + 1) * sizeof(*add));
            ok = ok && rem && add;
            for (size_t i = 0; ok && i < rv->n_removes; i++) {
                zone_db_entry_t *r = rv->removes[i];
                if (find_zone_exact_in_view(ov, r->domain) == r) rem[nrem++] = r;
            }
            for (size_t i = 0; ok && i < rv->n_adds; i++) {
                zone_db_entry_t *a = rv->adds[i];
                dbreg_zone_t *z = dbreg_find(rv, a->domain, dns_name_hash_ci(a->domain));
                if (z && z->entry == a && !z->shadowed && find_zone_exact_in_view(ov, a->domain) != a)
                    add[nadd++] = a;
            }
            if (nrem > 1) qsort(rem, nrem, sizeof(*rem), cmp_ptr);
        }
        if (ok) {
            vs->entries = calloc(ov->zone_count + nadd ? ov->zone_count + nadd : 1, sizeof(zone_db_entry_t *));
            ok = vs->entries != NULL;
        }
        if (ok) {
            size_t k = 0;
            for (size_t i = 0; i < ov->zone_count; i++) {
                zone_db_entry_t *e = ov->entries[i];
                if (!e || (nrem && ptr_in_sorted(rem, nrem, e))) continue;
                dbreg_entry_ref(e);
                vs->entries[k++] = e;
            }
            for (size_t i = 0; i < nadd; i++) {
                dbreg_entry_ref(add[i]);
                vs->entries[k++] = add[i];
            }
            vs->zone_count = k;
            changes += (int)(nrem + nadd);
            ok = view_build_hashes(vs);
        }
        free(rem);
        free(add);
        if (!ok) {
            free_zone_db_snapshot(ns);
            pthread_mutex_unlock(&g_zone_db_rebuild_lock);
            syslog(LOG_ERR, "[DB] out of memory publishing the zone changes; they are kept for the next try");
            return -1;
        }
    }
    uint64_t retire_epoch = rcu_writer_publish(&g_zone_db_active, ns);
    old_snap->retire_epoch = retire_epoch;
    dbreg_pending_drop_locked();
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    pthread_t gc_tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&gc_tid, &attr, gc_snapshot_thread, old_snap) != 0)
        syslog(LOG_ERR, "[DB] cannot start the snapshot cleanup thread; the old snapshot is kept");
    pthread_attr_destroy(&attr);
    return changes;
}

bool dbreg_walk(dbreg_cursor_t *cur, dbreg_walk_cb cb, void *ud) {
    bool done = true;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    while (done && cur->view < g_dbreg_nviews) {
        const dbreg_view_t *rv = &g_dbreg_views[cur->view];
        while (done && cur->bucket < rv->nb) {
            size_t i = 0;
            for (const dbreg_zone_t *z = rv->tab[cur->bucket]; z; z = z->next, i++) {
                if (i < cur->skip) continue;
                if (!cb(ud, rv->name, z)) {
                    cur->skip = i;
                    done = false;
                    break;
                }
            }
            if (done) {
                cur->bucket++;
                cur->skip = 0;
            }
        }
        if (done) {
            cur->view++;
            cur->bucket = 0;
            cur->skip = 0;
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    return done;
}

void dbreg_counts(size_t *total, size_t *rejected, size_t *shadowed) {
    size_t t = 0, r = 0, s = 0;
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        const dbreg_view_t *rv = &g_dbreg_views[v];
        for (size_t b = 0; b < rv->nb; b++) {
            for (const dbreg_zone_t *z = rv->tab[b]; z; z = z->next) {
                if (z->entry) t++;
                if (z->last_result == DBREG_REJECTED) r++;
                if (z->entry && z->shadowed) s++;
            }
        }
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
    if (total) *total = t;
    if (rejected) *rejected = r;
    if (shadowed) *shadowed = s;
}

void dbreg_reset(void) {
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    dbreg_pending_drop_locked();
    for (size_t v = 0; v < g_dbreg_nviews; v++) {
        dbreg_view_t *rv = &g_dbreg_views[v];
        for (size_t b = 0; b < rv->nb; b++) {
            dbreg_zone_t *z = rv->tab[b];
            while (z) {
                dbreg_zone_t *nx = z->next;
                if (z->entry) zone_entry_unref(z->entry);
                free(z->error);
                free(z);
                z = nx;
            }
        }
        free(rv->tab);
        free(rv->adds);
        free(rv->removes);
    }
    free(g_dbreg_views);
    g_dbreg_views = NULL;
    g_dbreg_nviews = g_dbreg_capviews = g_dbreg_hint = 0;
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

zone_config_t *db_zone_config_new(const char *domain) {
    zone_config_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->domain = strdup(domain);
    c->type = strdup("master");
    if (!c->domain || !c->type) {
        free_zone_config(c);
        return NULL;
    }
    return c;
}

static void free_zone_config_cb(void *p) {
    free_zone_config(p);
}

void db_entry_set_config(zone_db_entry_t *entry, const zone_config_t *cfg) {
    /* one writer per entry (the ingest thread working on the zone) */
    const zone_config_t *old = atomic_load_explicit(&entry->dbcfg, memory_order_relaxed);
    uint64_t epoch = rcu_writer_publish(&entry->dbcfg, cfg);
    if (old && !zone_retire_object(entry, (void *)old, free_zone_config_cb, epoch))
        syslog(LOG_ERR, "[DB] zone '%s': out of memory retiring the previous settings; they are leaked", entry->domain);
}

zone_db_snapshot_t *rebuild_zone_db_snapshot(
    server_config_t *active_config, 
    const char *catalog_view_name,
    zone_db_entry_t *catalog_entry_to_update,
    const zone_config_t *catalog_cfg,
    catalog_member_id_t *new_desired_members, int new_desired_count) 
{
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
    if (!new_snap) {
        abort_rebuild_snapshot(NULL, "new_snap");
        return NULL;
    }
    
    if (active_config) {
        // MODE: Full Config Reload
        
        int max_valid_members = 0;
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (!old_snap->views[v].entries) continue;
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
                    if (entry->catalog_member_count > 0) {
                        max_valid_members += entry->catalog_member_count;
                    }
                }
            }
        }
        catalog_member_id_t *valid_members = max_valid_members > 0 ? calloc(max_valid_members, sizeof(catalog_member_id_t)) : NULL;
        if (max_valid_members > 0 && !valid_members) {
            abort_rebuild_snapshot(new_snap, "valid_members");
            return NULL;
        }
        int valid_member_count = 0;
        
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (!old_snap->views[v].entries) continue;
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
                    if (entry->catalog_member_count > 0) {
                        const zone_config_t *zcfg = zone_entry_config(active_config, entry);
                        if (zcfg && zcfg->is_catalog) {
                            for (int k = 0; k < entry->catalog_member_count; k++) {
                                valid_members[valid_member_count++] = entry->catalog_members[k];
                            }
                        } else {
                            free_catalog_member_ids(entry->catalog_members, entry->catalog_member_count);
                            entry->catalog_members = NULL;
                            entry->catalog_member_count = 0;
                            
                            int p = 0;
                            while (p < g_pending_coo_count) {
                                if (strcasecmp(g_pending_coo[p].old_catalog, entry->domain) == 0) {
                                    if (p < g_pending_coo_count - 1) {
                                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                                    }
                                    g_pending_coo_count--;
                                } else {
                                    p++;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* 旧メンバーが有効かは (名前, unique-id) のハッシュで引く (メンバー数の 2 乗にしない) */
        int *vm_ht = NULL, *vm_chain = NULL;
        size_t vm_hsize = 0;
        catalog_member_hash_build(valid_members, valid_member_count, &vm_ht, &vm_chain, &vm_hsize);

        int view_count = 0;
        for (view_config_t *v = active_config->views; v; v = v->next) view_count++;
        
        new_snap->view_count = view_count;
        if (view_count > 0) {
            new_snap->views = calloc(view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "new_snap->views");
                return NULL;
            }
        }
        atomic_init(&new_snap->reader_count, 0);

        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            view_snapshot_t *vs = &new_snap->views[vidx];
            vs->name = v->name ? strdup(v->name) : strdup("");
            if (!vs->name) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "vs->name");
                return NULL;
            }
            vs->match_clients_count = v->match_clients_count;
            if (v->match_clients_count > 0) {
                vs->match_clients = calloc(v->match_clients_count, sizeof(char *));
                if (!vs->match_clients) {
                    { free(valid_members); free(vm_ht); free(vm_chain); }
                    abort_rebuild_snapshot(new_snap, "vs->match_clients");
                    return NULL;
                }
                for (int i = 0; i < v->match_clients_count; i++) {
                    if (v->match_clients[i]) {
                        vs->match_clients[i] = strdup(v->match_clients[i]);
                        if (!vs->match_clients[i]) {
                            { free(valid_members); free(vm_ht); free(vm_chain); }
                            abort_rebuild_snapshot(new_snap, "vs->match_clients[i]");
                            return NULL;
                        }
                    }
                }
                vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
            } else {
                vs->match_clients = NULL;
                vs->match_clients_parsed = NULL;
            }

            int static_count = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) static_count++;
            
            /* 同じ名前の旧 view。ゾーンごとの照合はその view のハッシュと設定の索引で行う
             * (旧エントリを線形に探すと reload がゾーン数の 2 乗になる) */
            view_snapshot_t *old_view = (old_snap && v->name) ? snapshot_find_view(old_snap, v->name) : NULL;

            int dynamic_count = 0;
            if (old_view && old_view->entries) {
                for (size_t oi = 0; oi < old_view->zone_count; oi++) {
                    zone_db_entry_t *entry = old_view->entries[oi];
                    if (entry && entry->is_catalog_member &&
                        catalog_member_index(valid_members, valid_member_count, vm_ht, vm_chain, vm_hsize,
                                             entry->domain, zone_entry_catalog_uid(entry)) >= 0 &&
                        !view_find_zone_config(v, entry->domain)) {
                        dynamic_count++;
                    }
                }
            }

            /* DB zones (beta design 4.5): the registry's entries of this view that no configured zone hides */
            zone_db_entry_t **db_list = NULL;
            size_t db_n = dbreg_collect_view_locked(v, old_view, &db_list);
            if (db_n == (size_t)-1) {
                { free(valid_members); free(vm_ht); free(vm_chain); }
                abort_rebuild_snapshot(new_snap, "db_list");
                return NULL;
            }

            vs->zone_count = static_count + dynamic_count + db_n;
            if (vs->zone_count > 0) {
                vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
                if (!vs->entries) {
                    free(db_list);
                    { free(valid_members); free(vm_ht); free(vm_chain); }
                    abort_rebuild_snapshot(new_snap, "vs->entries");
                    return NULL;
                }
            }
            
            int zidx = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) {
                zone_db_entry_t *entry = NULL;
                zone_db_entry_t *old = (old_view && z->domain) ? find_zone_exact_in_view(old_view, z->domain) : NULL;
                if (old) {
                    /* O-13: type が変わったゾーンと、静的ゾーンで上書きされたカタログ
                     * メンバーは再利用しない。is_secondary や EXPIRE、転送の状態は
                     * エントリ作成時に決まるので、新しいエントリを作る (旧エントリは
                     * 削除されたゾーンと同じく旧スナップショットとともに解放される)。*/
                    if (old->kind == zone_kind_from_type(z->type) && !old->is_catalog_member && old->source != ZONE_SRC_DB) {
                        entry = old;
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        /* B-3: ixfr-history may have changed; a lower depth drops the oldest diffs now */
                        ixfr_history_set_depth(entry, ixfr_history_effective(active_config, z));
                    } else {
                        syslog(LOG_NOTICE, "[Core] zone '%s' in view '%s' changed type or replaces a catalog member; recreating the zone entry",
                               z->domain, v->name ? v->name : "");
                    }
                }
                if (!entry) {
                    entry = create_new_zone_entry(z->domain, v->name);
                    if (entry) {
                        ixfr_history_set_depth(entry, ixfr_history_effective(active_config, z));
                        entry->kind = zone_kind_from_type(z->type);
                        entry->is_secondary = (entry->kind == ZONE_KIND_SECONDARY);
                    }
                    if (entry && z->file) {
                        reload_master_zone(entry, z);
                    }
                }
                if (!entry) {
                    syslog(LOG_ERR, "[Core] Failed to allocate memory for zone '%s' in view '%s', skipping this zone this reload cycle",
                           z->domain ? z->domain : "unknown", v->name ? v->name : "unknown");
                    continue;
                }
                vs->entries[zidx++] = entry;
            }

            /* 有効なカタログメンバーのうち、静的な zone{} で上書きされていないものを引き継ぐ
             * (dynamic_count と同じ判定) */
            if (old_view && old_view->entries) {
                for (size_t oi = 0; oi < old_view->zone_count; oi++) {
                    zone_db_entry_t *entry = old_view->entries[oi];
                    if (entry && entry->is_catalog_member &&
                        catalog_member_index(valid_members, valid_member_count, vm_ht, vm_chain, vm_hsize,
                                             entry->domain, zone_entry_catalog_uid(entry)) >= 0 &&
                        !view_find_zone_config(v, entry->domain)) {
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        ixfr_history_set_depth(entry, ixfr_history_effective(active_config, NULL));
                        vs->entries[zidx++] = entry;
                    }
                }
            }
            for (size_t k = 0; k < db_n; k++) {
                atomic_fetch_add_explicit(&db_list[k]->snapshot_refs, 1, memory_order_release);
                ixfr_history_set_depth(db_list[k], ixfr_history_effective(active_config, zone_entry_config(active_config, db_list[k])));
                vs->entries[zidx++] = db_list[k];
            }
            free(db_list);
            vs->zone_count = zidx;
        }
        { free(valid_members); free(vm_ht); free(vm_chain); }

    } else {
        // MODE: Catalog Delta Update
        if (!catalog_entry_to_update) {
            abort_rebuild_snapshot(new_snap, "null catalog_entry_to_update");
            return NULL;
        }
        
        // Step A: Update Pending CoO Intentions (acting as $OLDCATZ)
        {
            int p = 0;
            while (p < g_pending_coo_count) {
                if (strcasecmp(g_pending_coo[p].old_catalog, catalog_entry_to_update->domain) == 0) {
                    if (p < g_pending_coo_count - 1) {
                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                    }
                    g_pending_coo_count--;
                } else {
                    p++;
                }
            }
            for (int i = 0; i < new_desired_count; i++) {
                if (strlen(new_desired_members[i].coo_target) > 0) {
                    if (g_pending_coo_count >= g_pending_coo_capacity) {
                        size_t old_cap = g_pending_coo_capacity;
                        size_t new_cap = old_cap == 0 ? 16 : old_cap * 2;
                        pending_coo_t *tmp = realloc(g_pending_coo, new_cap * sizeof(pending_coo_t));
                        if (!tmp) {
                            syslog(LOG_ERR, "[Catalog] Failed to allocate memory for g_pending_coo (domain=%s); skipping CoO tracking for this member", new_desired_members[i].domain);
                            continue;
                        }
                        g_pending_coo = tmp;
                        g_pending_coo_capacity = new_cap;
                        memset(&g_pending_coo[old_cap], 0, (new_cap - old_cap) * sizeof(pending_coo_t));
                    }
                    strncpy(g_pending_coo[g_pending_coo_count].domain, new_desired_members[i].domain, sizeof(g_pending_coo[0].domain) - 1);
                    g_pending_coo[g_pending_coo_count].domain[sizeof(g_pending_coo[0].domain) - 1] = '\0';
                    strncpy(g_pending_coo[g_pending_coo_count].old_catalog, catalog_entry_to_update->domain, sizeof(g_pending_coo[0].old_catalog) - 1);
                    g_pending_coo[g_pending_coo_count].old_catalog[sizeof(g_pending_coo[0].old_catalog) - 1] = '\0';
                    strncpy(g_pending_coo[g_pending_coo_count].new_catalog, new_desired_members[i].coo_target, sizeof(g_pending_coo[0].new_catalog) - 1);
                    g_pending_coo[g_pending_coo_count].new_catalog[sizeof(g_pending_coo[0].new_catalog) - 1] = '\0';
                    g_pending_coo_count++;
                }
            }
        }

        int added_count = 0;
        int removed_count = 0;
        catalog_member_id_t *added_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *removed_members = calloc(catalog_entry_to_update->catalog_member_count > 0 ? catalog_entry_to_update->catalog_member_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *coo_evicted_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        if (!added_members || !removed_members || !coo_evicted_members) {
            if (added_members) free(added_members);
            if (removed_members) free(removed_members);
            if (coo_evicted_members) free(coo_evicted_members);
            abort_rebuild_snapshot(new_snap, "catalog member allocations");
            return NULL;
        }
        int coo_evicted_count = 0;

        int filtered_count = 0;
        view_snapshot_t *target_view = NULL;
        if (old_snap && old_snap->views) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (old_snap->views[v].name && catalog_view_name &&
                    strcasecmp(old_snap->views[v].name, catalog_view_name) == 0) {
                    target_view = &old_snap->views[v];
                    break;
                }
            }
        }

        // Ephemeral hash table for catalog_entry_to_update->catalog_members
        int *cur_hash_table = NULL;
        int *cur_chain_next = NULL;
        size_t cur_hash_size = 0;
        int cur_count = catalog_entry_to_update->catalog_member_count;
        catalog_member_hash_build(catalog_entry_to_update->catalog_members, cur_count,
                                  &cur_hash_table, &cur_chain_next, &cur_hash_size);

        for (int i = 0; i < new_desired_count; i++) {
            int cur_idx = catalog_member_index(catalog_entry_to_update->catalog_members, cur_count,
                                               cur_hash_table, cur_chain_next, cur_hash_size,
                                               new_desired_members[i].domain, new_desired_members[i].unique_id);
            bool found = cur_idx >= 0;
            if (found && target_view &&
                !catalog_groups_equal(&new_desired_members[i], &catalog_entry_to_update->catalog_members[cur_idx])) {
                /* R-28: group だけの変更はメンバーの削除と追加にしない (RFC 9432 §4.3.2, §5.4) */
                zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                if (existing && existing->is_catalog_member &&
                    strcasecmp(zone_entry_catalog_owner(existing), catalog_entry_to_update->domain) == 0) {
                    catalog_entry_set_groups(existing, &new_desired_members[i]);
                    syslog(LOG_INFO, "[Catalog] Updated group property of member '%s' (unique-id: %s)",
                           existing->domain, new_desired_members[i].unique_id);
                }
            }

            bool member_accepted = true;
            bool needs_creation = true;

            if (!found) {
                if (target_view) {
                    zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                    if (existing && existing->source == ZONE_SRC_DB) {
                        /* the DB zone keeps its place: two entries of one name in a view would answer unpredictably.
                         * (A full reconfiguration lets the catalog member win, beta design 4.5.) */
                        syslog(LOG_WARNING, "[Catalog] Zone '%s' generated member '%s' which collides with a zone from the database. Skipping.",
                               catalog_entry_to_update->domain, new_desired_members[i].domain);
                        member_accepted = false;
                    } else if (existing && existing->is_catalog_member) {
                        if (strcasecmp(zone_entry_catalog_owner(existing), catalog_entry_to_update->domain) != 0) {
                            bool valid_coo = false;
                            for (int p = 0; p < g_pending_coo_count; p++) {
                                if (strcasecmp(g_pending_coo[p].domain, new_desired_members[i].domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].old_catalog, zone_entry_catalog_owner(existing)) == 0 &&
                                    strcasecmp(g_pending_coo[p].new_catalog, catalog_entry_to_update->domain) == 0) {
                                    valid_coo = true; break;
                                }
                            }
                            if (valid_coo) {
                                zone_db_entry_t *old_catalog_entry = find_catalog_parent_in_snapshot(target_view, zone_entry_catalog_owner(existing));
                                if (old_catalog_entry) {
                                    remove_member_from_catalog_bookkeeping(old_catalog_entry, zone_entry_catalog_uid(existing), new_desired_members[i].domain);
                                }
                                if (strcmp(zone_entry_catalog_uid(existing), new_desired_members[i].unique_id) == 0) {
                                    // Retain state
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: retained state for '%s' (unique-id: %s), owner %s -> %s",
                                           existing->domain, zone_entry_catalog_uid(existing), zone_entry_catalog_owner(existing), catalog_entry_to_update->domain);
                                    char *new_owner = strdup(catalog_entry_to_update->domain);
                                    if (new_owner) {
                                        free(existing->owning_catalog_domain);
                                        existing->owning_catalog_domain = new_owner;
                                    }
                                    
                                    catalog_entry_set_groups(existing, &new_desired_members[i]);
                                    needs_creation = false;
                                } else {
                                    // State reset
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: evicted old state for '%s' (old unique-id: %s, new unique-id: %s)",
                                           existing->domain, zone_entry_catalog_uid(existing), new_desired_members[i].unique_id);
                                    strncpy(coo_evicted_members[coo_evicted_count].unique_id, zone_entry_catalog_uid(existing), sizeof(coo_evicted_members[coo_evicted_count].unique_id) - 1);
                                    strncpy(coo_evicted_members[coo_evicted_count].domain, existing->domain, sizeof(coo_evicted_members[coo_evicted_count].domain) - 1);
                                    coo_evicted_count++;
                                }
                            } else {
                                syslog(LOG_WARNING, "[Catalog] Name collision for '%s' between '%s' and '%s'. Ignoring.", 
                                       new_desired_members[i].domain, zone_entry_catalog_owner(existing), catalog_entry_to_update->domain);
                                member_accepted = false;
                            }
                        }
                    }
                }
            } else {
                needs_creation = false; // Already existed exactly in our catalog
            }

            if (member_accepted) {
                if (filtered_count != i) {
                    new_desired_members[filtered_count] = new_desired_members[i];
                }
                filtered_count++;
                if (needs_creation) {
                    added_members[added_count++] = new_desired_members[i];
                }
            } else {
                if (new_desired_members[i].groups) {
                    for (int g = 0; g < new_desired_members[i].group_count; g++) {
                        free(new_desired_members[i].groups[g]);
                    }
                    free(new_desired_members[i].groups);
                }
            }
        }
        if (cur_hash_table) free(cur_hash_table);
        if (cur_chain_next) free(cur_chain_next);
        new_desired_count = filtered_count;

        // Ephemeral hash table for new_desired_members
        int *des_hash_table = NULL;
        int *des_chain_next = NULL;
        size_t des_hash_size = 0;
        catalog_member_hash_build(new_desired_members, new_desired_count,
                                  &des_hash_table, &des_chain_next, &des_hash_size);

        for (int i = 0; i < catalog_entry_to_update->catalog_member_count; i++) {
            bool found = catalog_member_index(new_desired_members, new_desired_count,
                                              des_hash_table, des_chain_next, des_hash_size,
                                              catalog_entry_to_update->catalog_members[i].domain,
                                              catalog_entry_to_update->catalog_members[i].unique_id) >= 0;
            if (!found) {
                removed_members[removed_count++] = catalog_entry_to_update->catalog_members[i];
            }
        }
        if (des_hash_table) free(des_hash_table);
        if (des_chain_next) free(des_chain_next);

        zone_db_entry_t **new_entries = calloc(added_count > 0 ? added_count : 1, sizeof(zone_db_entry_t*));
        if (!new_entries) {
            free(added_members); free(removed_members); free(coo_evicted_members);
            abort_rebuild_snapshot(new_snap, "catalog new_entries");
            return NULL;
        }
        int actual_added_count = 0;
        /* Once the new members are placed in the catalog's view, that view owns
         * their initial reference and abort_rebuild_snapshot() frees them with
         * the snapshot. Error paths may free them directly only before then;
         * doing so afterwards was a use-after-free / double free. */
        bool new_entries_published = false;
        for (int i = 0; i < added_count; i++) {
            zone_db_entry_t *entry = create_new_zone_entry(added_members[i].domain, catalog_view_name);
            if (!entry) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                continue;
            }
            ixfr_history_set_depth(entry, ixfr_history_effective(active_config, NULL));
            entry->owning_catalog_domain = strdup(catalog_entry_to_update->domain);
            entry->catalog_member_unique_id = strdup(added_members[i].unique_id);
            if (!entry->owning_catalog_domain || !entry->catalog_member_unique_id) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                free_zone_db_entry(entry);
                continue;
            }
            syslog(LOG_INFO, "[Catalog] Added new member '%s' (unique-id: %s) owned by %s", added_members[i].domain, added_members[i].unique_id, catalog_entry_to_update->domain);
            entry->is_catalog_member = true;
            entry->source = ZONE_SRC_CATALOG;
            entry->kind = ZONE_KIND_SECONDARY;
            entry->is_secondary = true;
            if (added_members[i].group_count > 0) {
                entry->groups = calloc(added_members[i].group_count, sizeof(char*));
                if (entry->groups) {
                    entry->group_count = added_members[i].group_count;
                    for (int g = 0; g < added_members[i].group_count; g++) {
                        entry->groups[g] = strdup(added_members[i].groups[g]);
                    }
                }
            }
            bool has_master = catalog_cfg && zext(catalog_cfg)->masters_count > 0 && zext(catalog_cfg)->masters[0].ip != NULL;
            if (has_master || (catalog_cfg && zext(catalog_cfg)->tsig_key)) {
                entry->catalog_master = calloc(1, sizeof(*entry->catalog_master));
                if (entry->catalog_master && has_master) {
                    strncpy(entry->catalog_master->ip, zext(catalog_cfg)->masters[0].ip, sizeof(entry->catalog_master->ip) - 1);
                    entry->catalog_master->port = zext(catalog_cfg)->masters[0].port;
                }
                if (entry->catalog_master && zext(catalog_cfg)->tsig_key)
                    strncpy(entry->catalog_master->tsig_key, zext(catalog_cfg)->tsig_key, sizeof(entry->catalog_master->tsig_key) - 1);
            }
            atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
            new_entries[actual_added_count++] = entry;
        }
        added_count = actual_added_count;

        new_snap->view_count = old_snap ? old_snap->view_count : 0;
        if (new_snap->view_count > 0) {
            new_snap->views = calloc(new_snap->view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                for (int k = 0; k < actual_added_count; k++) {
                    if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                }
                free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                abort_rebuild_snapshot(new_snap, "catalog new_snap->views");
                return NULL;
            }
            atomic_init(&new_snap->reader_count, 0);

            // Build ephemeral hash table for deleted members (removed + coo_evicted)
            int total_deleted = removed_count + coo_evicted_count;
            int *del_hash_table = NULL;
            int *del_chain_next = NULL;
            size_t del_hash_size = 0;
            if (total_deleted > 0) {
                size_t p = 256;
                while (p < (size_t)total_deleted * 2) p <<= 1;
                del_hash_size = p;
                del_hash_table = malloc(del_hash_size * sizeof(int));
                del_chain_next = malloc(total_deleted * sizeof(int));
                if (del_hash_table && del_chain_next) {
                    for (size_t k = 0; k < del_hash_size; k++) del_hash_table[k] = -1;
                    for (int j = 0; j < total_deleted; j++) {
                        const catalog_member_id_t *del = (j < removed_count) ? 
                            &removed_members[j] : &coo_evicted_members[j - removed_count];
                        uint32_t h = calc_catalog_member_hash(del->domain, del->unique_id);
                        size_t idx = h & (del_hash_size - 1);
                        del_chain_next[j] = del_hash_table[idx];
                        del_hash_table[idx] = j;
                    }
                } else {
                    if (del_hash_table) { free(del_hash_table); del_hash_table = NULL; }
                    if (del_chain_next) { free(del_chain_next); del_chain_next = NULL; }
                    del_hash_size = 0;
                }
            }

            for (size_t v = 0; v < old_snap->view_count; v++) {
                view_snapshot_t *vs = &new_snap->views[v];
                vs->name = old_snap->views[v].name ? strdup(old_snap->views[v].name) : strdup("");
                if (!vs->name) {
                    if (del_hash_table) free(del_hash_table);
                    if (del_chain_next) free(del_chain_next);
                    for (int k = 0; k < actual_added_count; k++) {
                        if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                    }
                    free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                    abort_rebuild_snapshot(new_snap, "catalog vs->name");
                    return NULL;
                }
                vs->match_clients_count = old_snap->views[v].match_clients_count;
                if (vs->match_clients_count > 0) {
                    vs->match_clients = calloc(vs->match_clients_count, sizeof(char *));
                    if (!vs->match_clients) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        for (int k = 0; k < actual_added_count; k++) {
                            if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                        }
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->match_clients");
                        return NULL;
                    }
                    for (int i = 0; i < vs->match_clients_count; i++) {
                        if (old_snap->views[v].match_clients[i]) {
                            vs->match_clients[i] = strdup(old_snap->views[v].match_clients[i]);
                            if (!vs->match_clients[i]) {
                                if (del_hash_table) free(del_hash_table);
                                if (del_chain_next) free(del_chain_next);
                                for (int k = 0; k < actual_added_count; k++) {
                                    if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                                }
                                free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                                abort_rebuild_snapshot(new_snap, "catalog vs->match_clients[i]");
                                return NULL;
                            }
                        }
                    }
                    vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
                } else {
                    vs->match_clients = NULL;
                    vs->match_clients_parsed = NULL;
                }

                if (catalog_view_name && strcasecmp(vs->name, catalog_view_name) == 0) {
                    size_t max_zones = old_snap->views[v].zone_count + added_count;
                    vs->entries = calloc(max_zones > 0 ? max_zones : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        for (int k = 0; k < actual_added_count; k++) {
                            if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                        }
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->entries");
                        return NULL;
                    }
                    
                    int zidx = 0;
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        if (!entry) continue;
                        bool is_removed = false;
                        if (entry->is_catalog_member && del_hash_table && del_chain_next) {
                            uint32_t h = calc_catalog_member_hash(entry->domain, zone_entry_catalog_uid(entry));
                            size_t idx = h & (del_hash_size - 1);
                            for (int j = del_hash_table[idx]; j != -1; j = del_chain_next[j]) {
                                const catalog_member_id_t *del = (j < removed_count) ? 
                                    &removed_members[j] : &coo_evicted_members[j - removed_count];
                                if (strcasecmp(entry->domain, del->domain) == 0 &&
                                    strcmp(zone_entry_catalog_uid(entry), del->unique_id) == 0) {
                                    is_removed = true;
                                    break;
                                }
                            }
                        } else if (entry->is_catalog_member && total_deleted > 0) {
                            for (int j = 0; j < removed_count; j++) {
                                if (strcasecmp(entry->domain, removed_members[j].domain) == 0 &&
                                    strcmp(zone_entry_catalog_uid(entry), removed_members[j].unique_id) == 0) {
                                    is_removed = true; break;
                                }
                            }
                            if (!is_removed) {
                                for (int j = 0; j < coo_evicted_count; j++) {
                                    if (strcasecmp(entry->domain, coo_evicted_members[j].domain) == 0 &&
                                        strcmp(zone_entry_catalog_uid(entry), coo_evicted_members[j].unique_id) == 0) {
                                        is_removed = true; break;
                                    }
                                }
                            }
                        }
                        if (!is_removed) {
                            atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                            vs->entries[zidx++] = entry;
                        }
                    }
                    
                    for (int i = 0; i < added_count; i++) {
                        vs->entries[zidx++] = new_entries[i];
                    }
                    new_entries_published = true;
                    vs->zone_count = zidx;
                } else {
                    vs->zone_count = old_snap->views[v].zone_count;
                    vs->entries = calloc(vs->zone_count > 0 ? vs->zone_count : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        for (int k = 0; k < actual_added_count; k++) {
                            if (new_entries[k] && !new_entries_published) free_zone_db_entry(new_entries[k]);
                        }
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog other vs->entries");
                        return NULL;
                    }
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        if (entry) {
                            atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                            vs->entries[i] = entry;
                        }
                    }
                }
            }
            if (del_hash_table) free(del_hash_table);
            if (del_chain_next) free(del_chain_next);
        }

        free(added_members);
        free(removed_members);
        free(coo_evicted_members);
        free(new_entries);

        if (catalog_entry_to_update) {
            // handled above
            if (catalog_entry_to_update->catalog_members) free_catalog_member_ids(catalog_entry_to_update->catalog_members, catalog_entry_to_update->catalog_member_count);
            catalog_entry_to_update->catalog_members = new_desired_members;
            catalog_entry_to_update->catalog_member_count = new_desired_count;
        }
    }

    for (size_t v = 0; v < new_snap->view_count; v++) {
        view_snapshot_t *vs = &new_snap->views[v];
        if (!view_build_hashes(vs)) {
            syslog(LOG_ERR, "[Core] Hash table allocation failed for view '%s', aborting snapshot rebuild", vs->name ? vs->name : "unknown");
            abort_rebuild_snapshot(new_snap, "hash_tables");
            return NULL;
        }
    }

    /* the registry is the source of truth: what the ingest threads queued for the old snapshot is in (or out of) this
     * one already (full configuration mode); the catalog delta copies the old entries, so its queue stays valid */
    if (active_config) dbreg_pending_drop_locked();
    uint64_t retire_epoch = rcu_writer_publish(&g_zone_db_active, new_snap);
    if (old_snap) {
        old_snap->retire_epoch = retire_epoch;
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    if (old_snap) {
        pthread_t gc_tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&gc_tid, &attr, gc_snapshot_thread, old_snap);
        pthread_attr_destroy(&attr);
    }

    return new_snap;
}

int rebuild_zone_db_from_config(server_config_t *config, bool skip_unchanged) {
    return rebuild_zone_db_from_config_ext(config, skip_unchanged, NULL, 0);
}

/* 戻り値: 読み込みに失敗したプライマリゾーンの数 (D-13)。スナップショットを作れなければ -1。
 * failed が NULL でなければ、失敗したゾーン名を ", " 区切りで入れる (入りきらなければ "..." で終える) */
int rebuild_zone_db_from_config_ext(server_config_t *config, bool skip_unchanged, char *failed, size_t failed_sz) {
    int nfailed = 0;
    if (failed && failed_sz > 0) failed[0] = '\0';
    /* 新しいエントリはスナップショットを作るときに読み込む。読み込めたものを下で 2 度読まない */
    uint64_t first_new_id = atomic_load_explicit(&g_zone_entry_id, memory_order_relaxed);
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(config, NULL, NULL, NULL, NULL, 0);
    if (!new_snap) {
        syslog(LOG_ERR, "[Core] Failed to rebuild zone DB snapshot from config due to allocation failure. Reload aborted.");
        return -1;
    }

    size_t since_retire = 0;
    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
            if (snap) {
                zone_db_entry_t *entry = snapshot_get_zone_in_view(snap, v->name, z->domain);
                if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                    struct stat st;
                    if (entry->id > first_new_id && atomic_load_explicit(&entry->publish_order, memory_order_seq_cst) != 0) {
                        /* この再構築で作って読み込み済み */
                    } else if (skip_unchanged && stat_via_dir_cache(z->file, &st) == 0 && entry->last_loaded_mtime != 0 && st.st_mtime == entry->last_loaded_mtime) {
                        syslog(LOG_DEBUG, "[Config] zone '%s' file unchanged (mtime match), skipping reload", z->domain);
                    } else if (reload_master_zone(entry, z) != RELOAD_OK) {
                        nfailed++;
                        if (failed && failed_sz > 0) {
                            size_t used = strlen(failed);
                            int w = snprintf(failed + used, failed_sz - used, "%s%s", used ? ", " : "", z->domain);
                            if (w < 0 || (size_t)w >= failed_sz - used) {
                                /* 入りきらない: 末尾を "..." にする */
                                if (failed_sz >= 4) memcpy(failed + failed_sz - 4, "...", 4);
                            }
                        }
                    } else if (++since_retire >= 1024) {
                        /* S2: 古い版をまとめて解放する (全ゾーンの 2 版分を同時に持たない) */
                        zone_retire_process(true);
                        since_retire = 0;
                    }
                }
                release_zone_snapshot(snap);
            }
        }
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            if (z->is_catalog && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
                if (snap) {
                    zone_db_entry_t *entry = snapshot_get_zone_in_view(snap, v->name, z->domain);
                    if (entry) {
                        catalog_process_membership(entry, z, v->name);
                    }
                    release_zone_snapshot(snap);
                }
            }
        }
    }

    /* S2: 兄弟ゾーンのアドレスを使うグルーを作り直す。以前は全ゾーンの arena を複製して prelink し
     * 直していた (Pass 2)。今は兄弟ゾーンが後から読み込まれた・変わった・増減したゾーンだけ、
     * グルーだけを差し替える。ゾーンの増減は公開を伴わないので必ず調べる。 */
    zone_glue_refresh_dependents(true);
    zone_retire_process(true);
    return nfailed;
}

void zone_arena_clear_data_pools(zone_arena_t *arena) {
  if (!arena) return;
  free(arena->image);
  arena->image = NULL;
  free(arena->glue);
  arena->glue = NULL;
  for (int i = 0; i < arena->data_pool_count; i++) {
    if (arena->data_pools[i]) {
      free(arena->data_pools[i]);
      arena->data_pools[i] = NULL;
    }
  }
  zone_arena_free_sorted_indexes(arena);
  if (arena->locations) {
    free(arena->locations);
    arena->locations = NULL;
    arena->location_count = 0;
  }
  if (arena->bind_location_tags) {
    free_ecs_tags_array(arena->bind_location_tags, arena->bind_location_tag_count);
    arena->bind_location_tags = NULL;
    arena->bind_location_tag_count = 0;
  }
  if (arena->bind_ecs_tags) {
    free_ecs_tags_array(arena->bind_ecs_tags, arena->bind_ecs_tag_count);
    arena->bind_ecs_tags = NULL;
    arena->bind_ecs_tag_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < arena->bind_ecs_trusted_resolver_count; i++) {
      free(arena->bind_ecs_trusted_resolvers[i]);
    }
    free(arena->bind_ecs_trusted_resolvers);
    arena->bind_ecs_trusted_resolvers = NULL;
    arena->bind_ecs_trusted_resolver_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers_parsed) {
    free(arena->bind_ecs_trusted_resolvers_parsed);
    arena->bind_ecs_trusted_resolvers_parsed = NULL;
  }
  arena->rcache_ok = false;
  atomic_store_explicit(&arena->generation, 0, memory_order_relaxed);
  arena->count = 0;
  arena->data_pool_count = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
}

/* S5 B-2: 公開済みのイメージ src->image から dst に builder を作る (UPDATE と IXFR で、公開済みのゾーンに差分を当てる前の
 * 複製の代わり)。dst は空にしてからイメージを zone_image_thaw() する: レコードはファイルの順、索引も作ってある。
 * 0 = 成功。失敗したら dst は空にする。 */
int thaw_zone_arena(const zone_version_t *src, zone_arena_t *dst) {
  zone_arena_clear_data_pools(dst);
  if (!src || !src->image) return -1;
  if (zone_image_thaw(src->image, dst) != 0) {
    zone_arena_clear_data_pools(dst);
    return -1;
  }
  return 0;
}
