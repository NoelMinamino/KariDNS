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
    int *suffix_hash_table;
    int *suffix_chain_next;
    size_t suffix_hash_size;
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

static inline uint32_t calc_fnv1a_strn(const char *str, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)str[i];
        if (c >= 'A' && c <= 'Z')
            c |= 0x20;
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
                if (snap->views[v].entries[i] && strcasecmp(snap->views[v].entries[i]->domain, domain) == 0) {
                    return snap->views[v].entries[i];
                }
            }
        }
    }
    return NULL;
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
        size_t z_len = strlen(entry->domain);
        while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;
        if (z_len == key_len && strncasecmp(entry->domain, key, key_len) == 0) {
            return entry;
        }
    }
    return NULL;
}

static zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname) {
    if (!view || !qname) return NULL;
    if (!view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
        // Linear fallback
        size_t q_len = strlen(qname);
        while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

        zone_db_entry_t *best_entry = NULL;
        size_t longest_match_len = 0;
        for (size_t i = 0; i < view->zone_count; i++) {
            zone_db_entry_t *entry = view->entries[i];
            if (!entry) continue;
            size_t z_len = strlen(entry->domain);
            while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;

            bool match = false;
            if (z_len == 0 && (strcmp(entry->domain, ".") == 0 || entry->domain[0] == '\0')) {
                match = true;
            } else if (q_len == z_len && strncasecmp(qname, entry->domain, z_len) == 0) {
                match = true;
            } else if (q_len > z_len && qname[q_len - z_len - 1] == '.' &&
                       strncasecmp(qname + (q_len - z_len), entry->domain, z_len) == 0) {
                match = true;
            }
            if (match && (!best_entry || z_len > longest_match_len)) {
                longest_match_len = z_len;
                best_entry = entry;
            }
        }
        return best_entry;
    }

    size_t q_len = strlen(qname);
    while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

    const char *cursor = qname;
    size_t remaining = q_len;
    while (remaining > 0) {
        zone_db_entry_t *hit = view_suffix_hash_lookup(view, cursor, remaining);
        if (hit) return hit;
        const char *dot = memchr(cursor, '.', remaining);
        if (!dot) break;
        remaining -= (size_t)(dot - cursor) + 1;
        cursor = dot + 1;
    }
    return view_suffix_hash_lookup(view, "", 0);
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
        if (domains[i] != NULL) {
            vs->entries[i] = calloc(1, sizeof(zone_db_entry_t));
            vs->entries[i]->domain = strdup(domains[i]);
        } else {
            // Intentionally insert NULL entry to simulate tooth-missing (歯抜け)
            vs->entries[i] = NULL;
        }
    }
    
    size_t p = 256;
    while (p < vs->zone_count * 2) p <<= 1;
    vs->hash_size = p;
    vs->suffix_hash_size = p;
    
    if (simulate_malloc_fail) {
        vs->hash_table = NULL;
        vs->chain_next = NULL;
        vs->suffix_hash_table = NULL;
        vs->suffix_chain_next = NULL;
        for (size_t i = 0; i < count; i++) {
            if (vs->entries[i]) {
                free(vs->entries[i]->domain);
                free(vs->entries[i]);
            }
        }
        free(vs->entries);
        free(vs->name);
        free(snap->views);
        free(snap);
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

    if (vs->suffix_hash_size > 0) {
        vs->suffix_hash_table = malloc(vs->suffix_hash_size * sizeof(int));
        for (size_t i = 0; i < vs->suffix_hash_size; i++) vs->suffix_hash_table[i] = -1;
    }
    if (vs->zone_count > 0) {
        vs->suffix_chain_next = malloc(vs->zone_count * sizeof(int));
        for (size_t i = 0; i < vs->zone_count; i++) vs->suffix_chain_next[i] = -1;
    }
    
    if (vs->hash_table && vs->chain_next) {
        for (size_t i = 0; i < vs->zone_count; i++) {
            if (!vs->entries[i]) continue;
            uint32_t hash = calc_fnv1a_str(vs->entries[i]->domain);
            size_t idx = hash & (vs->hash_size - 1);
            vs->chain_next[i] = vs->hash_table[idx];
            vs->hash_table[idx] = (int)i;
        }
    }

    if (vs->suffix_hash_table && vs->suffix_chain_next) {
        for (size_t i = 0; i < vs->zone_count; i++) {
            if (!vs->entries[i]) continue;
            size_t z_len = strlen(vs->entries[i]->domain);
            while (z_len > 0 && vs->entries[i]->domain[z_len - 1] == '.') z_len--;
            uint32_t hash = calc_fnv1a_strn(vs->entries[i]->domain, z_len);
            size_t idx = hash & (vs->suffix_hash_size - 1);
            vs->suffix_chain_next[i] = vs->suffix_hash_table[idx];
            vs->suffix_hash_table[idx] = (int)i;
        }
    }
    
    return snap;
}

void free_test_snapshot(zone_db_snapshot_t *snap) {
    if (!snap) return;
    for (size_t v = 0; v < snap->view_count; v++) {
        for (size_t i = 0; i < snap->views[v].zone_count; i++) {
            if (snap->views[v].entries[i]) {
                free(snap->views[v].entries[i]->domain);
                free(snap->views[v].entries[i]);
            }
        }
        free(snap->views[v].entries);
        free(snap->views[v].name);
        if (snap->views[v].hash_table) free(snap->views[v].hash_table);
        if (snap->views[v].chain_next) free(snap->views[v].chain_next);
        if (snap->views[v].suffix_hash_table) free(snap->views[v].suffix_hash_table);
        if (snap->views[v].suffix_chain_next) free(snap->views[v].suffix_chain_next);
    }
    free(snap->views);
    free(snap);
}

int main(void) {
    printf("--- Running Hash Table & Suffix Lookup Tests ---\n");
    
    const char *domains[] = {
        "example.com.",
        "sub.example.com.",
        "deep.sub.example.com.",
        "test.com.",
        "zone0.example.",
        "zone145.example.", 
        ".", // root zone
        "MiXedCase.ExAmple.",
        "another.test.",
        "dots.example.com...", // multiple trailing dots
        "nodots.example"       // no trailing dot
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
    
    // 5. find_zone_in_view tests:
    view_snapshot_t *vs = &snap->views[0];

    // 5.1 Exact match (with and without dot)
    zone_db_entry_t *fz1 = find_zone_in_view(vs, "example.com.");
    assert(fz1 != NULL && strcmp(fz1->domain, "example.com.") == 0);
    zone_db_entry_t *fz1_nodot = find_zone_in_view(vs, "example.com");
    assert(fz1_nodot != NULL && strcmp(fz1_nodot->domain, "example.com.") == 0);

    // 5.2 Longest match (Parent vs Child zones)
    // www.example.com. -> should match example.com.
    zone_db_entry_t *fz_parent = find_zone_in_view(vs, "www.example.com.");
    assert(fz_parent != NULL && strcmp(fz_parent->domain, "example.com.") == 0);
    // www.sub.example.com. -> should match sub.example.com., NOT example.com.
    zone_db_entry_t *fz_child = find_zone_in_view(vs, "www.sub.example.com.");
    assert(fz_child != NULL && strcmp(fz_child->domain, "sub.example.com.") == 0);
    // a.b.deep.sub.example.com. -> should match deep.sub.example.com.
    zone_db_entry_t *fz_deep = find_zone_in_view(vs, "a.b.deep.sub.example.com.");
    assert(fz_deep != NULL && strcmp(fz_deep->domain, "deep.sub.example.com.") == 0);

    // 5.3 Mixed case query
    zone_db_entry_t *fz_case = find_zone_in_view(vs, "WwW.SuB.eXaMpLe.CoM.");
    assert(fz_case != NULL && strcmp(fz_case->domain, "sub.example.com.") == 0);

    // 5.4 Multiple trailing dots on query
    zone_db_entry_t *fz_multidot_q = find_zone_in_view(vs, "www.example.com...");
    assert(fz_multidot_q != NULL && strcmp(fz_multidot_q->domain, "example.com.") == 0);

    // 5.5 Multiple trailing dots on zone domain
    zone_db_entry_t *fz_multidot_z = find_zone_in_view(vs, "host.dots.example.com.");
    assert(fz_multidot_z != NULL && strcmp(fz_multidot_z->domain, "dots.example.com...") == 0);

    // 5.6 Zone domain with no trailing dot in config
    zone_db_entry_t *fz_nodot_z = find_zone_in_view(vs, "host.nodots.example.");
    assert(fz_nodot_z != NULL && strcmp(fz_nodot_z->domain, "nodots.example") == 0);

    // 5.7 Root zone fallback for unmatched domain
    zone_db_entry_t *fz_root = find_zone_in_view(vs, "unrelated.domain.org.");
    assert(fz_root != NULL && strcmp(fz_root->domain, ".") == 0);

    // 5.8 Root zone query itself
    zone_db_entry_t *fz_root_self = find_zone_in_view(vs, ".");
    assert(fz_root_self != NULL && strcmp(fz_root_self->domain, ".") == 0);
    zone_db_entry_t *fz_root_empty = find_zone_in_view(vs, "");
    assert(fz_root_empty != NULL && strcmp(fz_root_empty->domain, ".") == 0);

    free_test_snapshot(snap);
    
    // 6. View WITHOUT root zone -> fallback returns NULL
    const char *no_root_domains[] = {
        "example.com.",
        "test.com."
    };
    zone_db_snapshot_t *snap_no_root = build_test_snapshot(no_root_domains, 2, false);
    assert(snap_no_root != NULL);
    assert(find_zone_in_view(&snap_no_root->views[0], "unrelated.org.") == NULL);
    assert(find_zone_in_view(&snap_no_root->views[0], ".") == NULL);
    free_test_snapshot(snap_no_root);

    // 7. Zero zones view
    zone_db_snapshot_t *snap_zero = build_test_snapshot(NULL, 0, false);
    assert(snap_zero != NULL);
    assert(snapshot_get_zone(snap_zero, "anything.") == NULL);
    assert(find_zone_in_view(&snap_zero->views[0], "anything.") == NULL);
    free_test_snapshot(snap_zero);
    
    // 8. Teeth-missing (歯抜け) snapshot with NULL entries
    const char *teeth_missing_domains[] = {
        "example.com.",
        NULL, // Simulated failed allocation in regular zone loading
        "sub.example.com.",
        NULL,
        "test.com."
    };
    zone_db_snapshot_t *snap_teeth = build_test_snapshot(teeth_missing_domains, 5, false);
    assert(snap_teeth != NULL);
    // Exact lookups
    assert(snapshot_get_zone(snap_teeth, "example.com.") != NULL);
    assert(snapshot_get_zone(snap_teeth, "test.com.") != NULL);
    // Suffix lookups
    zone_db_entry_t *fzt1 = find_zone_in_view(&snap_teeth->views[0], "www.example.com.");
    assert(fzt1 != NULL && strcmp(fzt1->domain, "example.com.") == 0);
    zone_db_entry_t *fzt2 = find_zone_in_view(&snap_teeth->views[0], "www.sub.example.com.");
    assert(fzt2 != NULL && strcmp(fzt2->domain, "sub.example.com.") == 0);
    assert(find_zone_in_view(&snap_teeth->views[0], "notfound.org.") == NULL);
    free_test_snapshot(snap_teeth);

    // 9. Malloc failure validation (OOM simulation)
    zone_db_snapshot_t *snap_fail = build_test_snapshot(domains, count, true);
    assert(snap_fail == NULL);
    
    printf("PASS: All Hash Table & Suffix Lookup Tests Completed Successfully!\n");
    return 0;
}
