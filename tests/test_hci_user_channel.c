// ========================================
//  nom du fichier: test_hci_user_channel.c
//  description courte: Unit tests for the HCI_CHANNEL_USER packet framing
//  (hci_user_channel_build_acl) and the open()-errno diagnostics
//  (hci_user_channel_strerror). The socket lifecycle itself
//  (open/close/send/read_bdaddr) needs a real adapter and root, like every
//  other HCI_CHANNEL_USER engine in this codebase, so it is not covered
//  here -- see hci_user_channel.h for its documented contract instead.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hci_user_channel.h"

#include <errno.h>
#include <string.h>

// A minimal SMP-sized payload lands right after the 9-byte ACL+L2CAP header,
// with every length field reflecting the payload alone (not the header).
static void test_build_acl_basic(void) {
    uint8_t buf[32];
    const uint8_t payload[] = { 0x01, 0x03, 0x00, 0x01, 0x07, 0x01, 0x01 }; // SMP Pairing Request
    int n = hci_user_channel_build_acl(buf, sizeof buf, 0x0040, 0x0006, payload, sizeof payload);

    CHECK(n == 9 + (int)sizeof payload);
    CHECK(buf[0] == 0x02); // HCI_ACLDATA_PKT
    CHECK(buf[1] == 0x40 && buf[2] == 0x00); // handle 0x0040, PB=00b, BC=00b
    uint16_t acl_len = (uint16_t)(buf[3] | (buf[4] << 8));
    CHECK(acl_len == 4 + sizeof payload); // L2CAP header + payload
    uint16_t l2cap_len = (uint16_t)(buf[5] | (buf[6] << 8));
    CHECK(l2cap_len == sizeof payload); // payload alone, not the L2CAP header
    uint16_t cid = (uint16_t)(buf[7] | (buf[8] << 8));
    CHECK(cid == 0x0006); // SMP fixed channel
    CHECK(memcmp(&buf[9], payload, sizeof payload) == 0);
}

// The connection handle's top 4 bits are reserved for PB/BC flags: a handle
// using all 12 low bits must not bleed into them.
static void test_build_acl_handle_masking(void) {
    uint8_t buf[16];
    int n = hci_user_channel_build_acl(buf, sizeof buf, 0x0fff, 0x0004, NULL, 0);
    CHECK(n == 9);
    CHECK(buf[1] == 0xff);
    CHECK(buf[2] == 0x0f); // high nibble (PB/BC) stays 0
}

// Zero-length payload is valid (e.g. an empty L2CAP signal) and writes no
// payload bytes.
static void test_build_acl_empty_payload(void) {
    uint8_t buf[16];
    int n = hci_user_channel_build_acl(buf, sizeof buf, 0x0001, 0x0004, NULL, 0);
    CHECK(n == 9);
}

// NULL out, or a non-empty payload with a NULL pointer, is rejected.
static void test_build_acl_invalid_args(void) {
    uint8_t buf[16];
    const uint8_t payload[] = { 0x01 };
    errno = 0;
    CHECK(hci_user_channel_build_acl(NULL, sizeof buf, 1, 4, payload, 1) == -1);
    CHECK(errno == EINVAL);

    errno = 0;
    CHECK(hci_user_channel_build_acl(buf, sizeof buf, 1, 4, NULL, 1) == -1);
    CHECK(errno == EINVAL);
}

// A buffer too small for the 9-byte header plus payload is rejected with
// ENOSPC, not a silent truncation.
static void test_build_acl_buffer_too_small(void) {
    uint8_t buf[9]; // room for the header only
    const uint8_t payload[] = { 0x01, 0x02 };
    errno = 0;
    CHECK(hci_user_channel_build_acl(buf, sizeof buf, 1, 4, payload, sizeof payload) == -1);
    CHECK(errno == ENOSPC);
}

// Every errno path returns a non-NULL, non-empty message, and distinct
// errnos that mean distinct things get distinct text.
static void test_strerror_coverage(void) {
    const char *perm = hci_user_channel_strerror(EPERM);
    const char *acc  = hci_user_channel_strerror(EACCES);
    const char *busy = hci_user_channel_strerror(EBUSY);
    const char *other = hci_user_channel_strerror(ENODEV);

    CHECK(perm != NULL && perm[0] != '\0');
    CHECK(acc != NULL && acc[0] != '\0');
    CHECK(busy != NULL && busy[0] != '\0');
    CHECK(other != NULL && other[0] != '\0');

    // EPERM and EACCES are both "permission denied" in this context.
    CHECK(strcmp(perm, acc) == 0);
    // EBUSY is a distinct diagnosis from permission errors.
    CHECK(strcmp(perm, busy) != 0);
    CHECK(strcmp(busy, other) != 0);
}

int main(void) {
    printf("test_hci_user_channel\n");
    test_build_acl_basic();
    test_build_acl_handle_masking();
    test_build_acl_empty_payload();
    test_build_acl_invalid_args();
    test_build_acl_buffer_too_small();
    test_strerror_coverage();
    return TEST_REPORT();
}
