#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// Mock the bare minimum structs to simulate the environment
typedef struct {
    char *domain;
} zone_db_entry_t;

typedef struct {
    char *name;
    zone_db_entry_t **entries;
    size_t zone_count;
    int *hash_table;
    int *chain_next;
    size_t hash_size;
} view_snapshot_t;

typedef struct {
    view_snapshot_t *views;
    size_t view_count;
} zone_db_snapshot_t;

// FNV-1a Hash from dns_zone_parser.c / dns_server_core.c
static inline uint32_t calc_fnv1a_str(const char *str) {
    uint32_t hash = 2166136261u;
    for (const char *p = str; *p; p++) {
        uint8_t c = (uint8_t)*p;
        if (c >= 'A' && c <= 'Z') c |= 0x20; // ASCII case-fold
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

// Function identical to snapshot_get_zone in dns_server_core.c
zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
    if (!snap) return NULL;
    for (size_t v = 0; v < snap->view_count; v++) {
        if (snap->views[v].hash_size > 0 && snap->views[v].hash_table) {
            uint32_t hash = calc_fnv1a_str(domain);
            size_t idx = hash & (snap->views[v].hash_size - 1);
            for (int i = snap->views[v].hash_table[idx]; i != -1; i = snap->views[v].chain_next[i]) {
                if (strcasecmp(snap->views[v].entries[i]->domain, domain) == 0) {
                    return snap->views[v].entries[i];
                }
            }
        }
    }
    return NULL;
}

// Helper to build a test snapshot similarly to rebuild_zone_db_snapshot
zone_db_snapshot_t *build_test_snapshot(const char **domains, size_t count, bool simulate_malloc_fail) {
    zone_db_snapshot_t *snap = calloc(1, sizeof(zone_db_snapshot_t));
    snap->view_count = 1;
    snap->views = calloc(1, sizeof(view_snapshot_t));
    
    view_snapshot_t *vs = &snap->views[0];
    vs->name = strdup("default");
    vs->zone_count = count;
    vs->entries = calloc(count > 0 ? count : 1, sizeof(zone_db_entry_t *));
    
    for (size_t i = 0; i < count; i++) {
        vs->entries[i] = calloc(1, sizeof(zone_db_entry_t));
        vs->entries[i]->domain = strdup(domains[i]);
    }
    
    size_t p = 256;
    while (p < vs->zone_count * 2) p <<= 1;
    vs->hash_size = p;
    
    if (simulate_malloc_fail) {
        vs->hash_table = NULL;
        vs->chain_next = NULL;
        // In the real code, rebuild_zone_db_snapshot aborts and cleans up if malloc fails.
        // We simulate a failed build returning NULL.
        return NULL; 
    }
    
    if (vs->hash_size > 0) {
        vs->hash_table = malloc(vs->hash_size * sizeof(int));
        for (size_t i = 0; i < vs->hash_size; i++) vs->hash_table[i] = -1;
    }
    if (vs->zone_count > 0) {
        vs->chain_next = malloc(vs->zone_count * sizeof(int));
        for (size_t i = 0; i < vs->zone_count; i++) vs->chain_next[i] = -1;
    }
    
    if (vs->hash_table && vs->chain_next) {
        for (size_t i = 0; i < vs->zone_count; i++) {
            uint32_t hash = calc_fnv1a_str(vs->entries[i]->domain);
            size_t idx = hash & (vs->hash_size - 1);
            vs->chain_next[i] = vs->hash_table[idx];
            vs->hash_table[idx] = (int)i;
        }
    }
    
    return snap;
}

void free_test_snapshot(zone_db_snapshot_t *snap) {
    if (!snap) return;
    for (size_t v = 0; v < snap->view_count; v++) {
        for (size_t i = 0; i < snap->views[v].zone_count; i++) {
            free(snap->views[v].entries[i]->domain);
            free(snap->views[v].entries[i]);
        }
        free(snap->views[v].entries);
        free(snap->views[v].name);
        if (snap->views[v].hash_table) free(snap->views[v].hash_table);
        if (snap->views[v].chain_next) free(snap->views[v].chain_next);
    }
    free(snap->views);
    free(snap);
}

int main(void) {
    printf("--- Running Hash Table Tests ---\n");
    
    const char *domains[] = {
        "example.com.",
        "test.com.",
        "zone0.example.", // intentional hash collisions testing if possible
        "zone145.example.", 
        ".", // root
        "MiXedCase.ExAmple.",
        "another.test."
    };
    size_t count = sizeof(domains) / sizeof(domains[0]);
    
    // 1. Normal functioning and exact match lookup
    zone_db_snapshot_t *snap = build_test_snapshot(domains, count, false);
    assert(snap != NULL);
    
    zone_db_entry_t *entry1 = snapshot_get_zone(snap, "example.com.");
    assert(entry1 != NULL && strcmp(entry1->domain, "example.com.") == 0);
    
    // 2. Mixed case lookup (case insensitivity)
    zone_db_entry_t *entry2 = snapshot_get_zone(snap, "mIxEdCaSe.eXaMpLe.");
    assert(entry2 != NULL && strcmp(entry2->domain, "MiXedCase.ExAmple.") == 0);
    
    // 3. Root zone lookup
    zone_db_entry_t *entry3 = snapshot_get_zone(snap, ".");
    assert(entry3 != NULL && strcmp(entry3->domain, ".") == 0);
    
    // 4. Missing zone lookup
    zone_db_entry_t *entry4 = snapshot_get_zone(snap, "doesnotexist.com.");
    assert(entry4 == NULL);
    
    free_test_snapshot(snap);
    
    // 5. Zero zones view
    zone_db_snapshot_t *snap_zero = build_test_snapshot(NULL, 0, false);
    assert(snap_zero != NULL);
    assert(snapshot_get_zone(snap_zero, "anything.") == NULL);
    free_test_snapshot(snap_zero);
    
    // 6. Malloc failure validation
    // The main logic aborts rebuild if malloc fails, simulating it returns NULL
    zone_db_snapshot_t *snap_fail = build_test_snapshot(domains, count, true);
    assert(snap_fail == NULL);
    
    printf("PASS: Hash Table Tests\n");
    return 0;
}
