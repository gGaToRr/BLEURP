// ========================================
//  nom du fichier: test_hci_scan.c
//  description courte: Unit tests for the LE scan command builders. Verifies
//  the exact HCI packet bytes for legacy and extended scan parameters/enable
//  commands, and the buffer-too-small rejection.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hci_scan.h"
#include "hci.h"

#include <errno.h>

// Legacy "Set Scan Parameters" for an active scan with the default timings.
static void test_legacy_params(void) {
    uint8_t buf[16];
    ssize_t n = hci_build_le_scan_params(
        buf, sizeof buf, HCI_LE_SCAN_ACTIVE,
        HCI_LE_SCAN_INTERVAL_DEFAULT, HCI_LE_SCAN_WINDOW_DEFAULT,
        HCI_LE_OWN_ADDR_PUBLIC, HCI_LE_FILTER_POLICY_ALL);
    const uint8_t want[] = {
        0x01,             // HCI command packet
        0x0b, 0x20,       // opcode 0x200b
        0x07,             // param length
        0x01,             // scan type = active
        0x10, 0x00,       // interval = 0x0010
        0x10, 0x00,       // window   = 0x0010
        0x00,             // own address type = public
        0x00,             // filter policy = accept all
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Legacy "Set Scan Enable" turning the scan on without duplicate filtering.
static void test_legacy_enable(void) {
    uint8_t buf[8];
    ssize_t n = hci_build_le_scan_enable(buf, sizeof buf,
                                         HCI_LE_SCAN_ENABLE, HCI_LE_FILTER_DUP_OFF);
    const uint8_t want[] = {0x01, 0x0c, 0x20, 0x02, 0x01, 0x00};
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Extended "Set Scan Parameters" on the LE 1M PHY, passive scan.
static void test_extended_params(void) {
    uint8_t buf[24];
    ssize_t n = hci_build_le_ext_scan_params(
        buf, sizeof buf, HCI_LE_SCAN_PASSIVE,
        HCI_LE_SCAN_INTERVAL_DEFAULT, HCI_LE_SCAN_WINDOW_DEFAULT,
        HCI_LE_OWN_ADDR_PUBLIC, HCI_LE_FILTER_POLICY_ALL);
    const uint8_t want[] = {
        0x01,             // HCI command packet
        0x41, 0x20,       // opcode 0x2041
        0x08,             // param length
        0x00,             // own address type = public
        0x00,             // filter policy = accept all
        0x01,             // scanning PHYs = LE 1M
        0x00,             // scan type = passive
        0x10, 0x00,       // interval = 0x0010
        0x10, 0x00,       // window   = 0x0010
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Extended "Set Scan Enable": on, no dup filter, scan until disabled.
static void test_extended_enable(void) {
    uint8_t buf[16];
    ssize_t n = hci_build_le_ext_scan_enable(
        buf, sizeof buf, HCI_LE_SCAN_ENABLE, HCI_LE_FILTER_DUP_OFF, 0x0000, 0x0000);
    const uint8_t want[] = {
        0x01,             // HCI command packet
        0x42, 0x20,       // opcode 0x2042
        0x06,             // param length
        0x01,             // enable
        0x00,             // filter duplicates = off
        0x00, 0x00,       // duration = 0
        0x00, 0x00,       // period   = 0
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// A buffer too small is rejected (ENOSPC propagates from the packet builder).
static void test_buffer_too_small(void) {
    uint8_t buf[4];
    errno = 0;
    ssize_t n = hci_build_le_scan_params(
        buf, sizeof buf, HCI_LE_SCAN_ACTIVE,
        HCI_LE_SCAN_INTERVAL_DEFAULT, HCI_LE_SCAN_WINDOW_DEFAULT,
        HCI_LE_OWN_ADDR_PUBLIC, HCI_LE_FILTER_POLICY_ALL);
    CHECK(n == -1);
    CHECK(errno == ENOSPC);
}

// hci_send rejects bad arguments before touching the socket.
static void test_send_bad_args(void) {
    uint8_t pkt[4] = {0x01, 0x0c, 0x20, 0x00};
    errno = 0;
    CHECK(hci_send(-1, pkt, sizeof pkt) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_send(1, NULL, 4) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_send(1, pkt, 0) == -1);
    CHECK(errno == EINVAL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_hci_scan\n");
    test_legacy_params();
    test_legacy_enable();
    test_extended_params();
    test_extended_enable();
    test_buffer_too_small();
    test_send_bad_args();
    return TEST_REPORT();
}
