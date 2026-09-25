// ========================================
//  nom du fichier: test_hci_cmd.c
//  description courte: Unit tests for the HCI command packet builder.
//  Checks header layout, parameter copying, buffer/argument validation,
//  and that the LE scan opcodes match the Bluetooth specification.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hci_cmd.h"
#include "hci.h"

#include <errno.h>

// A parameterless command is a 4-byte packet: type, little-endian opcode,
// and a zero length.
static void test_build_no_params(void) {
    uint8_t buf[8];
    ssize_t n = hci_build_command(buf, sizeof buf, HCI_OP_LE_SET_SCAN_ENABLE, NULL, 0);
    CHECK(n == 4);
    CHECK(buf[0] == 0x01); // HCI command packet type
    CHECK(buf[1] == 0x0c); // opcode LSB of 0x200c
    CHECK(buf[2] == 0x20); // opcode MSB of 0x200c
    CHECK(buf[3] == 0x00); // parameter length
}

// Parameters are appended right after the 4-byte header, in order.
static void test_build_with_params(void) {
    uint8_t buf[16];
    const uint8_t p[] = {0x01, 0x00}; // enable = 1, filter_duplicates = 0
    ssize_t n = hci_build_command(buf, sizeof buf, HCI_OP_LE_SET_SCAN_ENABLE, p, sizeof p);
    CHECK(n == 6);
    CHECK(buf[3] == 0x02);
    CHECK(buf[4] == 0x01);
    CHECK(buf[5] == 0x00);
}

// A buffer too small for header + params is rejected with ENOSPC.
static void test_build_buffer_too_small(void) {
    uint8_t buf[4];
    const uint8_t p[] = {0xaa};
    errno = 0;
    ssize_t n = hci_build_command(buf, sizeof buf, HCI_OP_LE_SET_SCAN_ENABLE, p, sizeof p);
    CHECK(n == -1);
    CHECK(errno == ENOSPC);
}

// A non-zero length with NULL params is a programming error (EINVAL).
static void test_build_null_params(void) {
    uint8_t buf[16];
    errno = 0;
    ssize_t n = hci_build_command(buf, sizeof buf, HCI_OP_LE_SET_SCAN_ENABLE, NULL, 3);
    CHECK(n == -1);
    CHECK(errno == EINVAL);
}

// Opcode composition must match the Bluetooth Core specification values.
static void test_opcode_values(void) {
    CHECK(HCI_OP_LE_SET_SCAN_PARAMS == 0x200b);
    CHECK(HCI_OP_LE_SET_SCAN_ENABLE == 0x200c);
    CHECK(HCI_OP_LE_SET_EXT_SCAN_PARAMS == 0x2041);
    CHECK(HCI_OP_LE_SET_EXT_SCAN_ENABLE == 0x2042);
    CHECK(HCI_OP_READ_LOCAL_VERSION == 0x1001);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_hci_cmd\n");
    test_build_no_params();
    test_build_with_params();
    test_build_buffer_too_small();
    test_build_null_params();
    test_opcode_values();
    return TEST_REPORT();
}
