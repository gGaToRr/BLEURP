// ========================================
//  nom du fichier: test_addr_priv.c
//  description courte: Unit tests for BLE address privacy classification.
//  Covers public/BR-EDR addresses and the three random sub-types (static,
//  RPA, NRPA) decoded from the two most-significant address bits, plus the
//  trackable predicate and display labels.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "addr_priv.h"

#include <string.h>

// Addresses are stored in HCI byte order (little-endian), so addr[5] is the
// most-significant byte and its top two bits select the random sub-type.

// A public LE address is a fixed IEEE MAC: always trackable.
static void test_public(void) {
    uint8_t a[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    CHECK(addr_privacy(a, ADDR_TYPE_LE_PUBLIC) == ADDR_PRIV_PUBLIC);
    CHECK(addr_is_trackable(ADDR_PRIV_PUBLIC) == true);
}

// A BR/EDR (classic) address is likewise a fixed public address.
static void test_bredr(void) {
    uint8_t a[6] = {0, 0, 0, 0, 0, 0xC0}; // MSB bits ignored for public types
    CHECK(addr_privacy(a, ADDR_TYPE_BREDR) == ADDR_PRIV_PUBLIC);
}

// Random address, top bits 0b11 -> static random (stable until reboot).
static void test_static_random(void) {
    uint8_t a[6] = {1, 2, 3, 4, 5, 0xF3}; // 0b11110011
    CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_STATIC_RANDOM);
    CHECK(addr_is_trackable(ADDR_PRIV_STATIC_RANDOM) == true);
}

// Random address, top bits 0b01 -> resolvable private address (rotates).
static void test_rpa(void) {
    uint8_t a[6] = {1, 2, 3, 4, 5, 0x53}; // 0b01010011
    CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_RPA);
    CHECK(addr_is_trackable(ADDR_PRIV_RPA) == false);
}

// Random address, top bits 0b00 -> non-resolvable private address (rotates).
static void test_nrpa(void) {
    uint8_t a[6] = {1, 2, 3, 4, 5, 0x12}; // 0b00010010
    CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_NRPA);
    CHECK(addr_is_trackable(ADDR_PRIV_NRPA) == false);
}

// Random address with the reserved 0b10 pattern: treated conservatively as
// non-trackable (classified NRPA) since it is not a stable identifier.
static void test_reserved_pattern(void) {
    uint8_t a[6] = {1, 2, 3, 4, 5, 0x92}; // 0b10010010
    CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_NRPA);
    CHECK(addr_is_trackable(ADDR_PRIV_NRPA) == false);
}

// The boundary values of each random sub-type range are classified correctly.
static void test_boundaries(void) {
    uint8_t a[6] = {0};
    a[5] = 0x00; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_NRPA);
    a[5] = 0x3F; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_NRPA);
    a[5] = 0x40; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_RPA);
    a[5] = 0x7F; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_RPA);
    a[5] = 0xC0; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_STATIC_RANDOM);
    a[5] = 0xFF; CHECK(addr_privacy(a, ADDR_TYPE_LE_RANDOM) == ADDR_PRIV_STATIC_RANDOM);
}

// Labels are short, stable, lower-case identifiers for the UI.
static void test_labels(void) {
    CHECK(strcmp(addr_privacy_label(ADDR_PRIV_PUBLIC), "public") == 0);
    CHECK(strcmp(addr_privacy_label(ADDR_PRIV_STATIC_RANDOM), "static") == 0);
    CHECK(strcmp(addr_privacy_label(ADDR_PRIV_RPA), "rpa") == 0);
    CHECK(strcmp(addr_privacy_label(ADDR_PRIV_NRPA), "nrpa") == 0);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_addr_priv\n");
    test_public();
    test_bredr();
    test_static_random();
    test_rpa();
    test_nrpa();
    test_reserved_pattern();
    test_boundaries();
    test_labels();
    return TEST_REPORT();
}
