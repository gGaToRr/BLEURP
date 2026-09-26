// ========================================
//  nom du fichier: test_att.c
//  description courte: Unit tests for the ATT codec: byte-for-byte request
//  builders (MTU, Read By Group Type/Type, Find Info, Read, Write, Write
//  Command), response parsers (Error, MTU) and the grouped-list iterator.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "att.h"

#include <errno.h>

// Compare the first sizeof(want) bytes of a built PDU.
#define EXPECT_BYTES(n, buf, want) do {                     \
    CHECK((n) == (ssize_t)sizeof(want));                    \
    for (size_t _i = 0; _i < sizeof(want); _i++)            \
        CHECK((buf)[_i] == (want)[_i]);                     \
} while (0)

// Exchange MTU Request: opcode + client RX MTU (little-endian).
static void test_exchange_mtu(void) {
    uint8_t b[8];
    ssize_t n = att_build_exchange_mtu(b, sizeof b, 0x0200);
    const uint8_t want[] = {0x02, 0x00, 0x02};
    EXPECT_BYTES(n, b, want);
}

// Read By Group Type Request for primary services over the full range.
static void test_read_by_group(void) {
    uint8_t b[16];
    ssize_t n = att_build_read_by_group_type(b, sizeof b, 0x0001, 0xffff,
                                             GATT_UUID_PRIMARY_SERVICE);
    const uint8_t want[] = {0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28};
    EXPECT_BYTES(n, b, want);
}

// Read By Type Request for characteristics.
static void test_read_by_type(void) {
    uint8_t b[16];
    ssize_t n = att_build_read_by_type(b, sizeof b, 0x0001, 0xffff,
                                       GATT_UUID_CHARACTERISTIC);
    const uint8_t want[] = {0x08, 0x01, 0x00, 0xff, 0xff, 0x03, 0x28};
    EXPECT_BYTES(n, b, want);
}

// Find Information Request over a range.
static void test_find_info(void) {
    uint8_t b[8];
    ssize_t n = att_build_find_information(b, sizeof b, 0x0001, 0xffff);
    const uint8_t want[] = {0x04, 0x01, 0x00, 0xff, 0xff};
    EXPECT_BYTES(n, b, want);
}

// Read Request by handle.
static void test_read(void) {
    uint8_t b[8];
    ssize_t n = att_build_read(b, sizeof b, 0x0005);
    const uint8_t want[] = {0x0a, 0x05, 0x00};
    EXPECT_BYTES(n, b, want);
}

// Write Request: opcode + handle + value.
static void test_write_req(void) {
    uint8_t b[16];
    const uint8_t v[] = {0x01, 0x00};
    ssize_t n = att_build_write(b, sizeof b, 0x0010, v, sizeof v);
    const uint8_t want[] = {0x12, 0x10, 0x00, 0x01, 0x00};
    EXPECT_BYTES(n, b, want);
}

// Write Command: opcode + handle + value, no ack.
static void test_write_cmd(void) {
    uint8_t b[16];
    const uint8_t v[] = {0xab};
    ssize_t n = att_build_write_command(b, sizeof b, 0x0010, v, sizeof v);
    const uint8_t want[] = {0x52, 0x10, 0x00, 0xab};
    EXPECT_BYTES(n, b, want);
}

// A buffer too small and NULL value are rejected.
static void test_build_errors(void) {
    uint8_t b[2];
    errno = 0;
    CHECK(att_build_read(b, sizeof b, 0x0001) == -1);
    CHECK(errno == ENOSPC);
    uint8_t big[16];
    errno = 0;
    CHECK(att_build_write(big, sizeof big, 0x0001, NULL, 3) == -1);
    CHECK(errno == EINVAL);
}

// Error Response parsing.
static void test_parse_error(void) {
    const uint8_t pdu[] = {0x01, 0x12, 0x05, 0x00, 0x0a}; // write req, handle 5, err 0x0a
    struct att_error e;
    CHECK(att_parse_error(pdu, sizeof pdu, &e) == 0);
    CHECK(e.request_opcode == 0x12);
    CHECK(e.handle == 0x0005);
    CHECK(e.error_code == 0x0a);

    const uint8_t not_err[] = {0x03, 0x17, 0x00};
    errno = 0;
    CHECK(att_parse_error(not_err, sizeof not_err, &e) == -1);
    CHECK(errno == EBADMSG);
}

// Exchange MTU Response parsing.
static void test_parse_mtu_rsp(void) {
    const uint8_t pdu[] = {0x03, 0x17, 0x00};
    uint16_t mtu = 0;
    CHECK(att_parse_exchange_mtu_rsp(pdu, sizeof pdu, &mtu) == 0);
    CHECK(mtu == 0x0017);
    const uint8_t wrong[] = {0x0b, 0x00};
    errno = 0;
    CHECK(att_parse_exchange_mtu_rsp(wrong, sizeof wrong, &mtu) == -1);
    CHECK(errno == EBADMSG);
}

// Grouped-list iteration over a Read By Group Type Response.
static void test_list_iter(void) {
    // opcode 0x11, elem_len 6, two elements:
    //   [handle][end group][uuid16]
    const uint8_t pdu[] = {
        0x11, 0x06,
        0x01, 0x00, 0x05, 0x00, 0x0f, 0x18, // 1..5, 0x180f
        0x06, 0x00, 0x09, 0x00, 0x0a, 0x18, // 6..9, 0x180a
    };
    struct att_list it;
    CHECK(att_list_begin(pdu, sizeof pdu, &it) == 0);
    CHECK(it.elem_len == 6);

    const uint8_t *el;
    CHECK(att_list_next(&it, &el) == 1);
    CHECK(el[0] == 0x01 && el[1] == 0x00);          // handle 0x0001
    CHECK(el[4] == 0x0f && el[5] == 0x18);          // uuid 0x180f
    CHECK(att_list_next(&it, &el) == 1);
    CHECK(el[0] == 0x06);                           // handle 0x0006
    CHECK(att_list_next(&it, &el) == 0);            // exhausted
}

// A too-short response and a zero element length are rejected.
static void test_list_begin_bad(void) {
    const uint8_t small[] = {0x11};
    struct att_list it;
    errno = 0;
    CHECK(att_list_begin(small, sizeof small, &it) == -1);
    CHECK(errno == EBADMSG);
    const uint8_t zero[] = {0x11, 0x00};
    errno = 0;
    CHECK(att_list_begin(zero, sizeof zero, &it) == -1);
    CHECK(errno == EBADMSG);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_att\n");
    test_exchange_mtu();
    test_read_by_group();
    test_read_by_type();
    test_find_info();
    test_read();
    test_write_req();
    test_write_cmd();
    test_build_errors();
    test_parse_error();
    test_parse_mtu_rsp();
    test_list_iter();
    test_list_begin_bad();
    return TEST_REPORT();
}
