#ifndef TEST_ZONE_SLOTS_H
#define TEST_ZONE_SLOTS_H

/*
 * S5 B-3: zone_db_entry_t no longer embeds two builder arenas (rcu.arena_a / rcu.arena_b); a published version is a heap
 * zone_version_t. Tests that build a zone by hand in "the entry's arena" ask for a slot here: test_zone_slot(&entry, 0 or 1)
 * is a zone_arena_t that belongs to the entry (keyed by the entry's address, made on first use, empty). It is a builder
 * like any other; to publish it a test stores `&slot->ver` in entry.rcu.active (a version that is not heap-allocated is
 * never freed with the entry, the test destroys the slot itself with zone_arena_destroy()).
 * test_zone_slots_release(&entry) destroys both slots and forgets the entry (tests that reuse one stack address for several
 * entries call it, or simply zone_arena_destroy() each slot they used: a destroyed slot is empty again).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dns_server_internal.h"

#define TEST_ZONE_SLOTS_MAX 512

typedef struct {
  const void *key;
  zone_arena_t slot[2];
} test_zone_slot_t;

static test_zone_slot_t g_test_zone_slots[TEST_ZONE_SLOTS_MAX];

static inline zone_arena_t *test_zone_slot(const void *entry, int which) {
  test_zone_slot_t *free_slot = NULL;
  for (int i = 0; i < TEST_ZONE_SLOTS_MAX; i++) {
    if (g_test_zone_slots[i].key == entry) return &g_test_zone_slots[i].slot[which & 1];
    if (!g_test_zone_slots[i].key && !free_slot) free_slot = &g_test_zone_slots[i];
  }
  if (!free_slot) {
    fprintf(stderr, "test_zone_slot: out of slots\n");
    abort();
  }
  free_slot->key = entry;
  zone_arena_init(&free_slot->slot[0]);
  zone_arena_init(&free_slot->slot[1]);
  return &free_slot->slot[which & 1];
}

static inline void test_zone_slots_release(const void *entry) {
  for (int i = 0; i < TEST_ZONE_SLOTS_MAX; i++) {
    if (g_test_zone_slots[i].key != entry) continue;
    zone_arena_destroy(&g_test_zone_slots[i].slot[0]);
    zone_arena_destroy(&g_test_zone_slots[i].slot[1]);
    g_test_zone_slots[i].key = NULL;
  }
}

/* Frees what an entry published through the code under test (a heap version, the IXFR ring) and its slots. For a
 * stack entry that is done with. */
static inline void test_entry_release(zone_db_entry_t *entry) {
  zone_version_t *v = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_version_free(v);
  atomic_store_explicit(&entry->rcu.active, &zone_version_empty, memory_order_release);
  ixfr_history_clear(&entry->ixfr_history);
  test_zone_slots_release(entry);
}

#endif
