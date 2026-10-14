#ifndef TEST_ZEXT_H
#define TEST_ZEXT_H
/* S6a: ゾーンのオプション (zone_ext_t) をテストから書くための補助。
 * tzx(&z)->field = ... で z->ext を必要なら確保して返す。確保したブロックは記録して
 * 終了まで到達可能にしておく (LeakSanitizer に漏れとして出さない)。テストの z は
 * 手で組んだ構造体なので、free_zone_config() は呼ばれない。 */
#include "../dns_config_parser.h"

#define TZX_MAX 8192
static zone_ext_t *tzx_registry[TZX_MAX];
static int tzx_registry_n;

static inline zone_ext_t *tzx(zone_config_t *z) {
  if (!z->ext) {
    zone_ext_t *x = zone_ext_mut(z);
    if (x && tzx_registry_n < TZX_MAX) tzx_registry[tzx_registry_n++] = x;
    return x;
  }
  return z->ext;
}
#endif
