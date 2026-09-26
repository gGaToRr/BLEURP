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
#include <string.h>

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

// --- Varied payloads: lock down little-endian encoding with non-defaults ---

// Legacy params: passive scan, custom interval/window, random address, and a
// non-default filter policy. Verifies the 16-bit values are little-endian.
static void test_legacy_params_varied(void) {
    uint8_t buf[16];
    ssize_t n = hci_build_le_scan_params(
        buf, sizeof buf, HCI_LE_SCAN_PASSIVE,
        0x00a0, 0x0050, /*own=*/0x01, /*policy=*/0x01);
    const uint8_t want[] = {
        0x01, 0x0b, 0x20, 0x07,
        0x00,             // passive
        0xa0, 0x00,       // interval 0x00a0 (LE)
        0x50, 0x00,       // window   0x0050 (LE)
        0x01,             // own address type = random
        0x01,             // filter policy = filter accept list
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Extended enable with duplicate filtering on and non-zero duration/period.
static void test_extended_enable_varied(void) {
    uint8_t buf[16];
    ssize_t n = hci_build_le_ext_scan_enable(
        buf, sizeof buf, HCI_LE_SCAN_ENABLE, HCI_LE_FILTER_DUP_ON,
        0x0100, 0x0200);
    const uint8_t want[] = {
        0x01, 0x42, 0x20, 0x06,
        0x01,             // enable
        0x01,             // filter duplicates = on
        0x00, 0x01,       // duration 0x0100 (LE)
        0x00, 0x02,       // period   0x0200 (LE)
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// --- Scan start/stop mode switch ---

// An unknown mode is rejected with EINVAL before any I/O.
static void test_scan_mode_invalid(void) {
    errno = 0;
    CHECK(hci_scan_start(-1, (enum hci_scan_mode)99, HCI_LE_SCAN_ACTIVE) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_scan_stop(-1, (enum hci_scan_mode)99) == -1);
    CHECK(errno == EINVAL);
}

// With a bad fd the commands build fine but the send fails (EINVAL), proving
// each mode reaches the send path.
static void test_scan_mode_paths(void) {
    errno = 0;
    CHECK(hci_scan_start(-1, HCI_SCAN_MODE_LEGACY, HCI_LE_SCAN_ACTIVE) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_scan_start(-1, HCI_SCAN_MODE_EXTENDED, HCI_LE_SCAN_PASSIVE) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_scan_stop(-1, HCI_SCAN_MODE_LEGACY) == -1);
    CHECK(errno == EINVAL);
}

// --- Advertising report dispatch ---

// Capture buffer for dispatched reports.
enum { CAP_MAX = 8 };
static struct hci_adv_report g_cap[CAP_MAX];
static int g_cap_n;

// Record each dispatched report for later inspection.
static void cap_cb(const struct hci_adv_report *r, void *user) {
    (void)user;
    if (g_cap_n < CAP_MAX) g_cap[g_cap_n] = *r;
    g_cap_n++;
}

// Build a single-report legacy advertising event. Returns its length.
static size_t make_legacy_adv(uint8_t *b, uint8_t addr_type,
                              const uint8_t addr[6], const uint8_t *data,
                              uint8_t dlen, int8_t rssi) {
    size_t o = 0;
    b[o++] = HCI_EVT_LE_META;
    size_t plen = o++;                       // filled at the end
    b[o++] = HCI_SUBEVT_LE_ADV_REPORT;
    b[o++] = 0x01;                           // num reports
    b[o++] = 0x00;                           // event type
    b[o++] = addr_type;
    memcpy(&b[o], addr, 6); o += 6;
    b[o++] = dlen;
    memcpy(&b[o], data, dlen); o += dlen;
    b[o++] = (uint8_t)rssi;
    b[plen] = (uint8_t)(o - 2);
    return o;
}

// Build a single-report extended advertising event. Returns its length.
static size_t make_ext_adv(uint8_t *b, uint8_t addr_type,
                           const uint8_t addr[6], const uint8_t *data,
                           uint8_t dlen, int8_t rssi) {
    size_t o = 0;
    b[o++] = HCI_EVT_LE_META;
    size_t plen = o++;
    b[o++] = HCI_SUBEVT_LE_EXT_ADV_REPORT;
    b[o++] = 0x01;                           // num reports
    b[o++] = 0x13; b[o++] = 0x00;            // event type (2 bytes)
    b[o++] = addr_type;
    memcpy(&b[o], addr, 6); o += 6;
    b[o++] = 0x01;                           // primary PHY
    b[o++] = 0x00;                           // secondary PHY
    b[o++] = 0x00;                           // advertising SID
    b[o++] = 0x7f;                           // TX power
    b[o++] = (uint8_t)rssi;                  // RSSI
    b[o++] = 0x00; b[o++] = 0x00;            // periodic interval
    b[o++] = 0x00;                           // direct address type
    memset(&b[o], 0, 6); o += 6;             // direct address
    b[o++] = dlen;
    memcpy(&b[o], data, dlen); o += dlen;
    b[plen] = (uint8_t)(o - 2);
    return o;
}

// A legacy report is decoded field by field.
static void test_dispatch_legacy(void) {
    g_cap_n = 0;
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const uint8_t data[] = {0x02, 0x01, 0x06};
    uint8_t buf[64];
    size_t n = make_legacy_adv(buf, 0x00, addr, data, sizeof data, -70);
    int r = hci_dispatch_event(buf, n, cap_cb, NULL);
    CHECK(r == 1);
    CHECK(g_cap_n == 1);
    CHECK(g_cap[0].extended == false);
    CHECK(g_cap[0].addr_type == 0x00);
    CHECK(memcmp(g_cap[0].address, addr, 6) == 0);
    CHECK(g_cap[0].rssi == -70);
    CHECK(g_cap[0].data_len == 3);
    CHECK(g_cap[0].data[0] == 0x02 && g_cap[0].data[2] == 0x06);
}

// An extended report is decoded, including the negative RSSI.
static void test_dispatch_extended(void) {
    g_cap_n = 0;
    const uint8_t addr[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const uint8_t data[] = {0x02, 0x01, 0x06, 0x03};
    uint8_t buf[64];
    size_t n = make_ext_adv(buf, 0x01, addr, data, sizeof data, -59);
    int r = hci_dispatch_event(buf, n, cap_cb, NULL);
    CHECK(r == 1);
    CHECK(g_cap[0].extended == true);
    CHECK(g_cap[0].addr_type == 0x01);
    CHECK(memcmp(g_cap[0].address, addr, 6) == 0);
    CHECK(g_cap[0].rssi == -59);
    CHECK(g_cap[0].data_len == 4);
    CHECK(g_cap[0].event_type == 0x0013);
}

// Two legacy reports in one event are both dispatched.
static void test_dispatch_legacy_multi(void) {
    g_cap_n = 0;
    const uint8_t a1[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t a2[6] = {7, 8, 9, 10, 11, 12};
    uint8_t buf[64];
    size_t o = 0;
    buf[o++] = HCI_EVT_LE_META;
    size_t plen = o++;
    buf[o++] = HCI_SUBEVT_LE_ADV_REPORT;
    buf[o++] = 0x02;                         // two reports
    buf[o++] = 0x00; buf[o++] = 0x00;        // report 1: type, addr_type
    memcpy(&buf[o], a1, 6); o += 6;
    buf[o++] = 0x01; buf[o++] = 0xaa;        // data_len 1, data
    buf[o++] = (uint8_t)(-40);               // rssi
    buf[o++] = 0x00; buf[o++] = 0x01;        // report 2: type, addr_type
    memcpy(&buf[o], a2, 6); o += 6;
    buf[o++] = 0x00;                         // data_len 0
    buf[o++] = (uint8_t)(-80);               // rssi
    buf[plen] = (uint8_t)(o - 2);
    int r = hci_dispatch_event(buf, o, cap_cb, NULL);
    CHECK(r == 2);
    CHECK(g_cap_n == 2);
    CHECK(g_cap[0].rssi == -40);
    CHECK(g_cap[1].rssi == -80);
    CHECK(g_cap[1].addr_type == 0x01);
    CHECK(memcmp(g_cap[1].address, a2, 6) == 0);
}

// A truncated report (missing trailing RSSI) is rejected with EBADMSG.
static void test_dispatch_truncated(void) {
    g_cap_n = 0;
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const uint8_t data[] = {0x02, 0x01, 0x06};
    uint8_t buf[64];
    size_t n = make_legacy_adv(buf, 0x00, addr, data, sizeof data, -70);
    errno = 0;
    CHECK(hci_dispatch_event(buf, n - 1, cap_cb, NULL) == -1);
    CHECK(errno == EBADMSG);
}

// Non-advertising events are ignored (return 0, nothing dispatched).
static void test_dispatch_ignores_other(void) {
    g_cap_n = 0;
    uint8_t buf[8] = {HCI_EVT_CMD_COMPLETE, 0x04, 0x01, 0x01, 0x10, 0x00, 0x00};
    CHECK(hci_dispatch_event(buf, sizeof buf, cap_cb, NULL) == 0);
    // An LE meta event with an unrelated sub-event is also ignored.
    uint8_t le[4] = {HCI_EVT_LE_META, 0x02, 0x01, 0x00};
    CHECK(hci_dispatch_event(le, sizeof le, cap_cb, NULL) == 0);
    CHECK(g_cap_n == 0);
}

// NULL arguments and too-short buffers are rejected.
static void test_dispatch_bad_args(void) {
    uint8_t buf[8] = {HCI_EVT_LE_META, 0x02, HCI_SUBEVT_LE_ADV_REPORT, 0x00};
    errno = 0;
    CHECK(hci_dispatch_event(NULL, 4, cap_cb, NULL) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_dispatch_event(buf, 4, NULL, NULL) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_dispatch_event(buf, 2, cap_cb, NULL) == -1);
    CHECK(errno == EBADMSG);
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
    test_legacy_params_varied();
    test_extended_enable_varied();
    test_scan_mode_invalid();
    test_scan_mode_paths();
    test_dispatch_legacy();
    test_dispatch_extended();
    test_dispatch_legacy_multi();
    test_dispatch_truncated();
    test_dispatch_ignores_other();
    test_dispatch_bad_args();
    return TEST_REPORT();
}
