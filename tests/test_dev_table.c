// ========================================
//  nom du fichier: test_dev_table.c
//  description courte: Unit tests for the discovered-device table. Covers
//  insert, update/merge (seen count, RSSI, name filling and preservation),
//  distinct addresses, RSSI sorting and bounds.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "dev_table.h"

#include <string.h>

static const uint8_t A1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t A2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

// A fresh table is empty.
static void test_init_empty(void) {
    struct dev_table t;
    CHECK(dev_table_init(&t) == 0);
    CHECK(dev_table_count(&t) == 0);
    CHECK(dev_table_at(&t, 0) == NULL);
    dev_table_free(&t);
}

// Inserting a new device records its fields and timestamps.
static void test_insert(void) {
    struct dev_table t;
    dev_table_init(&t);
    struct dev_entry *e = dev_table_upsert(&t, A1, 1, -50, "Watch", 1000);
    CHECK(e != NULL);
    CHECK(dev_table_count(&t) == 1);
    CHECK(memcmp(e->address, A1, 6) == 0);
    CHECK(e->rssi == -50);
    CHECK(e->best_rssi == -50);
    CHECK(e->seen == 1);
    CHECK(e->has_name == true);
    CHECK(strcmp(e->name, "Watch") == 0);
    CHECK(e->first_seen == 1000);
    CHECK(e->last_seen == 1000);
    dev_table_free(&t);
}

// Re-seeing the same address merges rather than duplicating.
static void test_update_merges(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -70, NULL, 1000);
    struct dev_entry *e = dev_table_upsert(&t, A1, 1, -55, NULL, 1005);
    CHECK(dev_table_count(&t) == 1);
    CHECK(e->seen == 2);
    CHECK(e->rssi == -55);       // latest
    CHECK(e->best_rssi == -55);  // strongest so far
    CHECK(e->last_seen == 1005);
    CHECK(e->first_seen == 1000);
    dev_table_free(&t);
}

// best_rssi keeps the strongest, even if a later report is weaker.
static void test_best_rssi(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -40, NULL, 1);
    struct dev_entry *e = dev_table_upsert(&t, A1, 1, -80, NULL, 2);
    CHECK(e->rssi == -80);
    CHECK(e->best_rssi == -40);
    dev_table_free(&t);
}

// A name arriving in a later report fills a previously empty name.
static void test_name_fills_later(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -60, NULL, 1);          // no name yet
    struct dev_entry *e = dev_table_upsert(&t, A1, 1, -60, "Tile", 2);
    CHECK(e->has_name == true);
    CHECK(strcmp(e->name, "Tile") == 0);
    dev_table_free(&t);
}

// An existing name is not wiped by a later empty report.
static void test_name_preserved(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -60, "Sensor", 1);
    struct dev_entry *e = dev_table_upsert(&t, A1, 1, -60, NULL, 2);
    CHECK(strcmp(e->name, "Sensor") == 0);
    e = dev_table_upsert(&t, A1, 1, -60, "", 3); // empty string also ignored
    CHECK(strcmp(e->name, "Sensor") == 0);
    dev_table_free(&t);
}

// Different addresses are tracked separately.
static void test_distinct(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -50, "One", 1);
    dev_table_upsert(&t, A2, 2, -60, "Two", 1);
    CHECK(dev_table_count(&t) == 2);
    dev_table_free(&t);
}

// Sorting orders the strongest signal first.
static void test_sort_by_rssi(void) {
    struct dev_table t;
    dev_table_init(&t);
    dev_table_upsert(&t, A1, 1, -80, "Far", 1);
    dev_table_upsert(&t, A2, 1, -40, "Near", 1);
    dev_table_sort_by_rssi(&t);
    CHECK(strcmp(dev_table_at(&t, 0)->name, "Near") == 0);
    CHECK(strcmp(dev_table_at(&t, 1)->name, "Far") == 0);
    CHECK(dev_table_at(&t, 2) == NULL);
    dev_table_free(&t);
}

// Growing beyond the initial capacity keeps every device.
static void test_growth(void) {
    struct dev_table t;
    dev_table_init(&t);
    for (int i = 0; i < 100; i++) {
        uint8_t a[6] = {(uint8_t)i, 1, 2, 3, 4, 5};
        CHECK(dev_table_upsert(&t, a, 1, (int8_t)(-i), NULL, 1) != NULL);
    }
    CHECK(dev_table_count(&t) == 100);
    dev_table_free(&t);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_dev_table\n");
    test_init_empty();
    test_insert();
    test_update_merges();
    test_best_rssi();
    test_name_fills_later();
    test_name_preserved();
    test_distinct();
    test_sort_by_rssi();
    test_growth();
    return TEST_REPORT();
}
