// ========================================
//  nom du fichier: dev_table.h
//  description courte: Discovered-device table. De-duplicates by address and
//  merges successive Device Found reports, keeping the best name, latest and
//  strongest RSSI, a seen counter and timestamps. Sortable by signal for a
//  wifite-style live view.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_DEV_TABLE_H
#define BLEURP_DEV_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

// One tracked device, accumulated across many advertising reports.
struct dev_entry {
    uint8_t  address[6];   // BD_ADDR (HCI byte order)
    uint8_t  addr_type;    // last address type seen
    int8_t   rssi;         // latest RSSI
    int8_t   best_rssi;    // strongest RSSI seen
    char     name[249];    // best name/label seen (NUL-terminated, "" if none)
    bool     has_name;
    uint32_t seen;         // number of reports merged
    time_t   first_seen;
    time_t   last_seen;
};

// Growable set of tracked devices.
struct dev_table {
    struct dev_entry *entries;
    size_t            count;
    size_t            cap;
};

// Initialize an empty table. Returns 0, or -1 with errno on allocation error.
int dev_table_init(struct dev_table *t);

// Release the table's memory and reset it to empty.
void dev_table_free(struct dev_table *t);

// Insert or update the device with this address. On an existing device the
// RSSI, seen count, last_seen and address type are updated, and `name` (when
// non-NULL and non-empty) replaces a missing or weaker name. `now` is the
// caller-supplied timestamp (for testability).
// Returns a pointer to the entry, or NULL with errno on allocation error.
struct dev_entry *dev_table_upsert(struct dev_table *t, const uint8_t addr[6],
                                   uint8_t addr_type, int8_t rssi,
                                   const char *name, time_t now);

// Sort the table by RSSI, strongest first (ties keep an arbitrary order).
void dev_table_sort_by_rssi(struct dev_table *t);

// Number of tracked devices.
size_t dev_table_count(const struct dev_table *t);

// Entry at index `i`, or NULL if out of range.
const struct dev_entry *dev_table_at(const struct dev_table *t, size_t i);

#endif // BLEURP_DEV_TABLE_H
