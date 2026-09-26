// ========================================
//  nom du fichier: test_hci_dev.c
//  description courte: Unit tests for the raw HCI socket module. Covers the
//  hardware-free parts: adapter-index validation and sockaddr_hci
//  construction, plus early rejection of a bad index by the open path.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hci_dev.h"

#include <errno.h>

// A valid request fills the family, device index and channel.
static void test_fill_addr_ok(void) {
    struct sockaddr_hci a;
    int r = bleurp_hci_fill_addr(&a, 0, BLEURP_HCI_CHANNEL_USER);
    CHECK(r == 0);
    CHECK(a.hci_family == BLEURP_AF_BLUETOOTH);
    CHECK(a.hci_dev == 0);
    CHECK(a.hci_channel == BLEURP_HCI_CHANNEL_USER);
}

// A negative or too-large adapter index is rejected with EINVAL.
static void test_fill_addr_bad_dev(void) {
    struct sockaddr_hci a;
    errno = 0;
    CHECK(bleurp_hci_fill_addr(&a, -1, BLEURP_HCI_CHANNEL_RAW) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(bleurp_hci_fill_addr(&a, BLEURP_HCI_MAX_DEV, BLEURP_HCI_CHANNEL_RAW) == -1);
    CHECK(errno == EINVAL);
}

// A NULL output pointer is rejected with EINVAL.
static void test_fill_addr_null(void) {
    errno = 0;
    CHECK(bleurp_hci_fill_addr(NULL, 0, BLEURP_HCI_CHANNEL_RAW) == -1);
    CHECK(errno == EINVAL);
}

// open() rejects a bad adapter index before attempting any syscall.
static void test_open_bad_dev(void) {
    errno = 0;
    int fd = bleurp_hci_open(-1, BLEURP_HCI_CHANNEL_USER);
    CHECK(fd == -1);
    CHECK(errno == EINVAL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_hci_dev\n");
    test_fill_addr_ok();
    test_fill_addr_bad_dev();
    test_fill_addr_null();
    test_open_bad_dev();
    return TEST_REPORT();
}
