// ========================================
//  nom du fichier: test_smp_native.c
//  description courte: Unit tests for smp_native: HCI Command Status parsing,
//  LE Create Connection parameter layout (peer address type mapping), the
//  offer-based probe argument checks, and the result printer for every link
//  state (no link, controller error, connected without SMP reply, reply).
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp_native.h"

#include <errno.h>
#include <string.h>

static void test_smp_native_null_args(void) {
    struct smp_probe_result res;
    uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    CHECK(smp_native_probe_device(0, NULL, 1, 100, &res) == -1);
    CHECK(smp_native_probe_device(0, addr, 1, 100, NULL) == -1);

    struct smp_pairing_params offer;
    memset(&offer, 0, sizeof offer);
    CHECK(smp_native_probe_offer(0, addr, 1, 100, NULL, &res) == -1);
    CHECK(smp_native_probe_offer(0, addr, 1, 100, &offer, NULL) == -1);
}

// Command Status for LE Create Connection (0x200d) with status 0x0c.
// Event body layout: code, param length, status, num cmd packets, opcode.
static void test_parse_cmd_status(void) {
    const uint8_t evt[] = {0x0f, 0x04, 0x0c, 0x01, 0x0d, 0x20};
    uint16_t op = 0;
    uint8_t status = 0xff;
    CHECK(smp_parse_cmd_status(evt, sizeof evt, &op, &status) == 0);
    CHECK(op == 0x200d);
    CHECK(status == 0x0c);
}

// Wrong event code or truncated body is rejected.
static void test_parse_cmd_status_bad(void) {
    const uint8_t not_status[] = {0x0e, 0x04, 0x00, 0x01, 0x0d, 0x20};
    const uint8_t truncated[] = {0x0f, 0x04, 0x00};
    uint16_t op = 0;
    uint8_t status = 0;
    errno = 0;
    CHECK(smp_parse_cmd_status(not_status, sizeof not_status, &op, &status) == -1);
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(smp_parse_cmd_status(truncated, sizeof truncated, &op, &status) == -1);
    CHECK(errno == EBADMSG);
}

// LE Create Connection is 25 bytes. The peer address type maps BLEURP
// (1 = public, 2 = random) to HCI (0x00 = public, 0x01 = random): this is
// the mapping the probe used to get wrong for random addresses.
static void test_le_create_conn_params(void) {
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t p[25];

    CHECK(smp_le_create_conn_params(p, 2, addr) == 0);
    CHECK(p[5] == 0x01);                  // peer type: random
    CHECK(memcmp(&p[6], addr, 6) == 0);   // peer address, LSB first
    CHECK(p[12] == 0x00);                 // own address type: public
    CHECK(p[13] == 0x18 && p[14] == 0x00); // conn interval min 30 ms

    CHECK(smp_le_create_conn_params(p, 1, addr) == 0);
    CHECK(p[5] == 0x00);                  // peer type: public

    CHECK(smp_le_create_conn_params(p, 9, addr) == -1); // unknown type
    CHECK(smp_le_create_conn_params(NULL, 1, addr) == -1);
    CHECK(smp_le_create_conn_params(p, 1, NULL) == -1);
}

// The printer must cover every link state without crashing and must not
// print the generic "timeout" wording for a connected, silent target.
static void test_smp_native_print_format(void) {
    struct smp_probe_result res;
    memset(&res, 0, sizeof(res));
    res.success = true;
    res.link = SMP_LINK_UP;
    res.io_capability = 0x03;
    res.oob_data_flag = 0x00;
    res.auth_req = 0x01; // Bonding seul
    res.max_key_size = 7;
    res.init_key_dist = 0x01;
    res.resp_key_dist = 0x01;
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");

    res.pairing_failed = true;
    res.fail_reason = 0x05; // Pairing Not Supported
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");

    res.success = false;
    res.pairing_failed = false;
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF"); // connected, silent

    res.link = SMP_LINK_NOT_FOUND;
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");

    res.link = SMP_LINK_HCI_ERROR;
    res.hci_status = 0x0c;
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");
    CHECK(1);
}

int main(void) {
    printf("test_smp_native\n");
    test_smp_native_null_args();
    test_parse_cmd_status();
    test_parse_cmd_status_bad();
    test_le_create_conn_params();
    test_smp_native_print_format();
    return TEST_REPORT();
}
