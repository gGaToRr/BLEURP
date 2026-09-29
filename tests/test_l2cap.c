// ========================================
//  nom du fichier: test_l2cap.c
//  description courte: Unit tests for the L2CAP address builder. Checks the
//  sockaddr_l2 fields (family, ATT CID, address bytes, type, zero PSM) and
//  the argument validation of the connect path.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "l2cap.h"
#include "hci_dev.h" // BLEURP_AF_BLUETOOTH

#include <errno.h>
#include <string.h>

// A valid request fills every sockaddr_l2 field.
static void test_fill_ok(void) {
    struct sockaddr_l2 a;
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    int r = bleurp_l2_fill_addr(&a, addr, BLEURP_BDADDR_LE_RANDOM, BLEURP_ATT_CID);
    CHECK(r == 0);
    CHECK(a.l2_family == BLEURP_AF_BLUETOOTH);
    CHECK(a.l2_psm == 0);
    CHECK(a.l2_cid == BLEURP_ATT_CID);
    CHECK(a.l2_bdaddr_type == BLEURP_BDADDR_LE_RANDOM);
    CHECK(memcmp(a.l2_bdaddr.b, addr, 6) == 0);
}

// NULL arguments are rejected with EINVAL.
static void test_fill_null(void) {
    struct sockaddr_l2 a;
    const uint8_t addr[6] = {0};
    errno = 0;
    CHECK(bleurp_l2_fill_addr(NULL, addr, BLEURP_BDADDR_LE_PUBLIC, BLEURP_ATT_CID) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(bleurp_l2_fill_addr(&a, NULL, BLEURP_BDADDR_LE_PUBLIC, BLEURP_ATT_CID) == -1);
    CHECK(errno == EINVAL);
}

// connect() rejects a NULL address before creating any socket.
static void test_connect_null(void) {
    errno = 0;
    CHECK(bleurp_l2_connect(NULL, BLEURP_BDADDR_LE_PUBLIC) == -1);
    CHECK(errno == EINVAL);
}

// The bounded-timeout variant rejects a NULL address the same way, before
// ever touching a socket or a timeout.
static void test_connect_timeout_null(void) {
    errno = 0;
    CHECK(bleurp_l2_connect_timeout(NULL, BLEURP_BDADDR_LE_PUBLIC, 1000) == -1);
    CHECK(errno == EINVAL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_l2cap\n");
    test_fill_ok();
    test_fill_null();
    test_connect_null();
    test_connect_timeout_null();
    return TEST_REPORT();
}
