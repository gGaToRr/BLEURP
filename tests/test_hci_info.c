// ========================================
//  nom du fichier: test_hci_info.c
//  description courte: Unit tests for controller-information parsing. Uses
//  fixed Command Complete event buffers to check field decoding, the
//  legacy/extended decision, and rejection of malformed or truncated input.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hci_info.h"
#include "hci.h"

#include <errno.h>
#include <string.h>

// Build a Read Local Version "Command Complete" event into `buf` for a given
// HCI version. Returns the number of bytes written (14).
static size_t make_local_version_evt(uint8_t *buf, uint8_t hci_version) {
    buf[0]  = HCI_EVT_CMD_COMPLETE;       // event code
    buf[1]  = 0x0c;                       // parameter total length (12)
    buf[2]  = 0x01;                       // num HCI command packets
    buf[3]  = 0x01;                       // opcode LSB (0x1001)
    buf[4]  = 0x10;                       // opcode MSB
    buf[5]  = 0x00;                       // status = success
    buf[6]  = hci_version;                // HCI_Version
    buf[7]  = 0x34; buf[8]  = 0x12;       // HCI_Revision = 0x1234
    buf[9]  = hci_version;                // LMP_Version (same here)
    buf[10] = 0x0f; buf[11] = 0x00;       // Manufacturer = 0x000f (Broadcom)
    buf[12] = 0x78; buf[13] = 0x56;       // LMP_Subversion = 0x5678
    return 14;
}

// A well-formed BT 5.0 event decodes every field and reports extended support.
static void test_parse_bt5(void) {
    uint8_t buf[14];
    size_t n = make_local_version_evt(buf, HCI_VER_BT_5_0);
    struct hci_local_version v;
    int r = hci_parse_local_version(buf, n, &v);
    CHECK(r == 0);
    CHECK(v.status == 0x00);
    CHECK(v.hci_version == HCI_VER_BT_5_0);
    CHECK(v.hci_revision == 0x1234);
    CHECK(v.manufacturer == 0x000f);
    CHECK(v.lmp_subversion == 0x5678);
    CHECK(hci_supports_extended(&v) == true);
}

// A BT 4.2 controller parses fine but has no extended support (legacy only).
static void test_parse_bt42_legacy(void) {
    uint8_t buf[14];
    size_t n = make_local_version_evt(buf, HCI_VER_BT_4_2);
    struct hci_local_version v;
    CHECK(hci_parse_local_version(buf, n, &v) == 0);
    CHECK(hci_supports_extended(&v) == false);
}

// A truncated buffer is rejected with EBADMSG.
static void test_parse_truncated(void) {
    uint8_t buf[14];
    make_local_version_evt(buf, HCI_VER_BT_5_0);
    struct hci_local_version v;
    errno = 0;
    CHECK(hci_parse_local_version(buf, 10, &v) == -1);
    CHECK(errno == EBADMSG);
}

// A different event code is rejected with EBADMSG.
static void test_parse_wrong_event(void) {
    uint8_t buf[14];
    size_t n = make_local_version_evt(buf, HCI_VER_BT_5_0);
    buf[0] = 0x0f; // not Command Complete
    struct hci_local_version v;
    errno = 0;
    CHECK(hci_parse_local_version(buf, n, &v) == -1);
    CHECK(errno == EBADMSG);
}

// A Command Complete for a different opcode is rejected with EBADMSG.
static void test_parse_wrong_opcode(void) {
    uint8_t buf[14];
    size_t n = make_local_version_evt(buf, HCI_VER_BT_5_0);
    buf[3] = 0x0c; buf[4] = 0x20; // 0x200c instead of 0x1001
    struct hci_local_version v;
    errno = 0;
    CHECK(hci_parse_local_version(buf, n, &v) == -1);
    CHECK(errno == EBADMSG);
}

// NULL arguments are rejected with EINVAL; the decision on NULL is false.
static void test_parse_null(void) {
    uint8_t buf[14];
    size_t n = make_local_version_evt(buf, HCI_VER_BT_5_0);
    struct hci_local_version v;
    errno = 0;
    CHECK(hci_parse_local_version(NULL, n, &v) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(hci_parse_local_version(buf, n, NULL) == -1);
    CHECK(errno == EINVAL);
    CHECK(hci_supports_extended(NULL) == false);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_hci_info\n");
    test_parse_bt5();
    test_parse_bt42_legacy();
    test_parse_truncated();
    test_parse_wrong_event();
    test_parse_wrong_opcode();
    test_parse_null();
    return TEST_REPORT();
}
