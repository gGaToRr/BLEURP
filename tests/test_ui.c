// ========================================
//  nom du fichier: test_ui.c
//  description courte: Unit tests for the pure UI helpers: RSSI colour bands,
//  signal-bar mapping, and row formatting (address, name, unknown fallback).
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "ui.h"
#include "dev_table.h"

#include <string.h>

// Signal bars increase with a stronger (less negative) RSSI.
static void test_bars(void) {
    CHECK(ui_rssi_bars(-40) == 5);
    CHECK(ui_rssi_bars(-100) == 0);
    CHECK(ui_rssi_bars(-70) < ui_rssi_bars(-50));
    CHECK(ui_rssi_bars(-70) >= 0 && ui_rssi_bars(-70) <= 5);
}

// Colour is non-NULL and differs between strong and weak signals.
static void test_color(void) {
    CHECK(ui_rssi_color(-40) != NULL);
    CHECK(ui_rssi_color(-100) != NULL);
    CHECK(strcmp(ui_rssi_color(-40), ui_rssi_color(-100)) != 0);
}

// A named device row contains its address and name.
static void test_row_named(void) {
    struct dev_entry e;
    memset(&e, 0, sizeof e);
    const uint8_t a[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(e.address, a, 6);
    e.addr_type = 1;
    e.rssi = -55;
    e.seen = 3;
    e.has_name = true;
    strcpy(e.name, "MyWatch");

    char buf[128];
    int n = ui_format_row(buf, sizeof buf, 1, &e);
    CHECK(n > 0);
    CHECK(strstr(buf, "66:55:44:33:22:11") != NULL); // displayed MSB-first
    CHECK(strstr(buf, "MyWatch") != NULL);
}

// A nameless device falls back to "(unknown)".
static void test_row_unknown(void) {
    struct dev_entry e;
    memset(&e, 0, sizeof e);
    e.rssi = -80;
    e.has_name = false;

    char buf[128];
    ui_format_row(buf, sizeof buf, 2, &e);
    CHECK(strstr(buf, "(unknown)") != NULL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_ui\n");
    test_bars();
    test_color();
    test_row_named();
    test_row_unknown();
    return TEST_REPORT();
}
