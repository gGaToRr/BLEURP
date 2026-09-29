// ========================================
//  nom du fichier: test_smp.c
//  description courte: Unit tests for the SMP codec: byte-for-byte Pairing
//  Request / Security Request builders and the Pairing Response / Pairing
//  Failed parsers used by the re-pairing downgrade probe.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp.h"

#include <errno.h>
#include <string.h>

// Compare the first sizeof(want) bytes of a built PDU.
#define EXPECT_BYTES(n, buf, want) do {                     \
    CHECK((n) == (ssize_t)sizeof(want));                    \
    for (size_t _i = 0; _i < sizeof(want); _i++)            \
        CHECK((buf)[_i] == (want)[_i]);                     \
} while (0)

// Pairing Request: opcode + the 6 fixed fields, in order.
static void test_build_pairing_request(void) {
    uint8_t b[8];
    struct smp_pairing_params p = {
        .io_capability = SMP_IO_CAP_NO_INPUT_NO_OUTPUT,
        .oob_data_flag = 0,
        .auth_req      = SMP_AUTHREQ_BONDING,
        .max_key_size  = 7,
        .init_key_dist = 0x0f,
        .resp_key_dist = 0x0f,
    };
    ssize_t n = smp_build_pairing_request(b, sizeof b, &p);
    const uint8_t want[] = {0x01, 0x03, 0x00, 0x01, 0x07, 0x0f, 0x0f};
    EXPECT_BYTES(n, b, want);
}

// A buffer too small to hold the PDU is rejected with ENOSPC.
static void test_build_pairing_request_small_buf(void) {
    uint8_t b[4];
    struct smp_pairing_params p = {0};
    errno = 0;
    CHECK(smp_build_pairing_request(b, sizeof b, &p) == -1);
    CHECK(errno == ENOSPC);
}

// NULL arguments are rejected with EINVAL.
static void test_build_pairing_request_null(void) {
    uint8_t b[8];
    struct smp_pairing_params p = {0};
    errno = 0;
    CHECK(smp_build_pairing_request(NULL, sizeof b, &p) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(smp_build_pairing_request(b, sizeof b, NULL) == -1);
    CHECK(errno == EINVAL);
}

// Security Request: opcode + the AuthReq byte.
static void test_build_security_request(void) {
    uint8_t b[4];
    ssize_t n = smp_build_security_request(b, sizeof b,
        SMP_AUTHREQ_BONDING | SMP_AUTHREQ_MITM | SMP_AUTHREQ_SC);
    const uint8_t want[] = {0x0b, 0x0d};
    EXPECT_BYTES(n, b, want);
}

// A Pairing Response round-trips through the parser.
static void test_parse_pairing_response(void) {
    const uint8_t pdu[] = {0x02, 0x03, 0x00, 0x0d, 0x10, 0x0f, 0x0f};
    struct smp_pairing_params out;
    memset(&out, 0, sizeof out);
    CHECK(smp_parse_pairing_response(pdu, sizeof pdu, &out) == 0);
    CHECK(out.io_capability == 0x03);
    CHECK(out.oob_data_flag == 0x00);
    CHECK(out.auth_req == 0x0d);
    CHECK(out.max_key_size == 0x10);
    CHECK(out.init_key_dist == 0x0f);
    CHECK(out.resp_key_dist == 0x0f);
}

// The wrong opcode, or a truncated PDU, is rejected with EBADMSG.
static void test_parse_pairing_response_bad(void) {
    const uint8_t wrong_opcode[] = {0x05, 0x03, 0x00, 0x0d, 0x10, 0x0f, 0x0f};
    struct smp_pairing_params out;
    errno = 0;
    CHECK(smp_parse_pairing_response(wrong_opcode, sizeof wrong_opcode, &out) == -1);
    CHECK(errno == EBADMSG);

    const uint8_t truncated[] = {0x02, 0x03, 0x00};
    errno = 0;
    CHECK(smp_parse_pairing_response(truncated, sizeof truncated, &out) == -1);
    CHECK(errno == EBADMSG);
}

// A Pairing Failed reason code round-trips through the parser.
static void test_parse_pairing_failed(void) {
    const uint8_t pdu[] = {0x05, 0x03}; // 0x03 = Authentication Requirements
    uint8_t reason = 0;
    CHECK(smp_parse_pairing_failed(pdu, sizeof pdu, &reason) == 0);
    CHECK(reason == 0x03);

    const uint8_t wrong_opcode[] = {0x02, 0x03};
    errno = 0;
    CHECK(smp_parse_pairing_failed(wrong_opcode, sizeof wrong_opcode, &reason) == -1);
    CHECK(errno == EBADMSG);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_smp\n");
    test_build_pairing_request();
    test_build_pairing_request_small_buf();
    test_build_pairing_request_null();
    test_build_security_request();
    test_parse_pairing_response();
    test_parse_pairing_response_bad();
    test_parse_pairing_failed();
    return TEST_REPORT();
}
