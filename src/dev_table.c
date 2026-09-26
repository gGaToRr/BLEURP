// ========================================
//  nom du fichier: dev_table.c
//  description courte: Implementation of the discovered-device table. Uses a
//  growable array keyed by address; upsert merges reports (RSSI, seen count,
//  best name), and sorting orders devices by signal strength.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "dev_table.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

// Initial number of device slots.
#define DEV_TABLE_INITIAL_CAP 16

// Initialize an empty table. See dev_table.h for the contract.
int dev_table_init(struct dev_table *t) {
    if (t == NULL) {
        errno = EINVAL;
        return -1;
    }
    t->entries = calloc(DEV_TABLE_INITIAL_CAP, sizeof *t->entries);
    if (t->entries == NULL) {
        return -1; // errno from calloc
    }
    t->count = 0;
    t->cap = DEV_TABLE_INITIAL_CAP;
    return 0;
}

// Release the table's memory. See dev_table.h for the contract.
void dev_table_free(struct dev_table *t) {
    if (t == NULL) {
        return;
    }
    free(t->entries);
    t->entries = NULL;
    t->count = 0;
    t->cap = 0;
}

// Find the entry for an address, or NULL if absent.
static struct dev_entry *find(struct dev_table *t, const uint8_t addr[6]) {
    for (size_t i = 0; i < t->count; i++) {
        if (memcmp(t->entries[i].address, addr, 6) == 0) {
            return &t->entries[i];
        }
    }
    return NULL;
}

// Double the capacity. Returns 0 or -1 with errno on failure.
static int grow(struct dev_table *t) {
    size_t ncap = t->cap * 2;
    struct dev_entry *n = realloc(t->entries, ncap * sizeof *n);
    if (n == NULL) {
        return -1; // errno from realloc
    }
    t->entries = n;
    t->cap = ncap;
    return 0;
}

// Insert or update a device. See dev_table.h for the contract.
struct dev_entry *dev_table_upsert(struct dev_table *t, const uint8_t addr[6],
                                   uint8_t addr_type, int8_t rssi,
                                   const char *name, time_t now) {
    if (t == NULL || addr == NULL) {
        errno = EINVAL;
        return NULL;
    }

    struct dev_entry *e = find(t, addr);
    if (e == NULL) {
        // New device: grow if needed, then append.
        if (t->count == t->cap && grow(t) < 0) {
            return NULL;
        }
        e = &t->entries[t->count++];
        memset(e, 0, sizeof *e);
        memcpy(e->address, addr, 6);
        e->best_rssi = rssi;
        e->first_seen = now;
        e->seen = 0; // incremented below
    }

    e->addr_type = addr_type;
    e->rssi = rssi;
    if (rssi > e->best_rssi) {
        e->best_rssi = rssi;
    }
    e->last_seen = now;
    e->seen++;

    // Fill or replace the name only when a real one is provided.
    if (name != NULL && name[0] != '\0') {
        strncpy(e->name, name, sizeof e->name - 1);
        e->name[sizeof e->name - 1] = '\0';
        e->has_name = true;
    }
    return e;
}

// Comparison for descending RSSI order.
static int cmp_rssi_desc(const void *a, const void *b) {
    const struct dev_entry *ea = a;
    const struct dev_entry *eb = b;
    if (ea->rssi < eb->rssi) return 1;
    if (ea->rssi > eb->rssi) return -1;
    return 0;
}

// Sort by RSSI, strongest first. See dev_table.h for the contract.
void dev_table_sort_by_rssi(struct dev_table *t) {
    if (t == NULL || t->count < 2) {
        return;
    }
    qsort(t->entries, t->count, sizeof *t->entries, cmp_rssi_desc);
}

// Number of tracked devices. See dev_table.h for the contract.
size_t dev_table_count(const struct dev_table *t) {
    return (t != NULL) ? t->count : 0;
}

// Entry at an index. See dev_table.h for the contract.
const struct dev_entry *dev_table_at(const struct dev_table *t, size_t i) {
    if (t == NULL || i >= t->count) {
        return NULL;
    }
    return &t->entries[i];
}
