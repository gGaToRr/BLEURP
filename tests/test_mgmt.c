// ========================================
//  nom du fichier: test_mgmt.c
//  description courte: Unit tests for the mgmt packet layer. Verifies the
//  exact command packet bytes (little-endian header + params) and header
//  parsing, including rejection of truncated or NULL input.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "mgmt.h"

#include <errno.h>

// A parameterless command is a 6-byte little-endian header.
static void test_build_no_params(void) {
    uint8_t buf[16];
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_READ_CONTROLLER_INFO, 0, NULL, 0);
    const uint8_t want[] = {
        0x04, 0x00, // opcode 0x0004 (LE)
        0x00, 0x00, // index 0
        0x00, 0x00, // param length 0
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Start Discovery on controller 0 with the LE address-type bitmask.
static void test_build_start_discovery(void) {
    uint8_t buf[16];
    const uint8_t p[] = {MGMT_ADDR_LE}; // 0x06
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_START_DISCOVERY, 0, p, sizeof p);
    const uint8_t want[] = {
        0x23, 0x00, // opcode 0x0023
        0x00, 0x00, // index 0
        0x01, 0x00, // param length 1
        0x06,       // address type = LE public | LE random
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// The controller index is encoded little-endian.
static void test_build_index_le(void) {
    uint8_t buf[16];
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_STOP_DISCOVERY, 0x0102, NULL, 0);
    CHECK(n == 6);
    CHECK(buf[2] == 0x02); // index LSB
    CHECK(buf[3] == 0x01); // index MSB
}

// A buffer too small is rejected with ENOSPC.
static void test_build_too_small(void) {
    uint8_t buf[4];
    errno = 0;
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_READ_CONTROLLER_INFO, 0, NULL, 0);
    CHECK(n == -1);
    CHECK(errno == ENOSPC);
}

// NULL params with a non-zero length is rejected with EINVAL.
static void test_build_null_params(void) {
    uint8_t buf[16];
    errno = 0;
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_START_DISCOVERY, 0, NULL, 3);
    CHECK(n == -1);
    CHECK(errno == EINVAL);
}

// A full header is decoded into opcode, index and length.
static void test_parse_header_ok(void) {
    // Command Complete event, controller 0, 4 param bytes.
    const uint8_t evt[] = {0x01, 0x00, 0x00, 0x00, 0x04, 0x00,
                           0x04, 0x00, 0x00, 0x00};
    struct mgmt_hdr h;
    int r = mgmt_parse_header(evt, sizeof evt, &h);
    CHECK(r == 0);
    CHECK(h.opcode == MGMT_EV_CMD_COMPLETE);
    CHECK(h.index == 0x0000);
    CHECK(h.len == 0x0004);
}

// The index field parses little-endian, including MGMT_INDEX_NONE.
static void test_parse_header_index_none(void) {
    const uint8_t evt[] = {0x02, 0x00, 0xff, 0xff, 0x00, 0x00};
    struct mgmt_hdr h;
    CHECK(mgmt_parse_header(evt, sizeof evt, &h) == 0);
    CHECK(h.opcode == MGMT_EV_CMD_STATUS);
    CHECK(h.index == MGMT_INDEX_NONE);
    CHECK(h.len == 0);
}

// A short buffer and NULL arguments are rejected.
static void test_parse_header_bad(void) {
    const uint8_t evt[] = {0x01, 0x00, 0x00};
    struct mgmt_hdr h;
    errno = 0;
    CHECK(mgmt_parse_header(evt, sizeof evt, &h) == -1);
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(mgmt_parse_header(NULL, 6, &h) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(mgmt_parse_header(evt, 6, NULL) == -1);
    CHECK(errno == EINVAL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_mgmt\n");
    test_build_no_params();
    test_build_start_discovery();
    test_build_index_le();
    test_build_too_small();
    test_build_null_params();
    test_parse_header_ok();
    test_parse_header_index_none();
    test_parse_header_bad();
    return TEST_REPORT();
}
