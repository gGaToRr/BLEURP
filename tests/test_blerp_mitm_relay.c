// ========================================
//  nom du fichier: test_blerp_mitm_relay.c
//  description courte: Unit tests for the BLERP single-channel MitM relay:
//  the tamper-vs-passthrough policy (blerp_relay_should_rewrite), and
//  blerp_run_single_channel_mitm's preconditions, which run before any
//  socket I/O so they need no root/hardware. The live relay loop itself
//  (two real HCI_CHANNEL_USER links) is exercised manually -- see
//  blerp_mitm_relay.h.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "blerp_mitm_relay.h"

#include <string.h>

// Only the two feature-negotiation opcodes are tampered with; every other
// SMP opcode -- including ones this relay never special-cases, like
// Keypress Notification -- passes through untouched.
static void test_should_rewrite(void) {
    CHECK(blerp_relay_should_rewrite(SMP_CODE_PAIRING_REQUEST) == true);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_PAIRING_RESPONSE) == true);

    CHECK(blerp_relay_should_rewrite(SMP_CODE_PAIRING_CONFIRM) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_PAIRING_RANDOM) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_PAIRING_FAILED) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_PUBLIC_KEY) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_DHKEY_CHECK) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_ENCRYPTION_INFO) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_MASTER_IDENT) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_SECURITY_REQUEST) == false);
    CHECK(blerp_relay_should_rewrite(SMP_CODE_KEYPRESS_NOTIFY) == false);
}

// blerp_run_single_channel_mitm must reject an unusable configuration
// before it ever opens an HCI socket, exactly like blerp_run_mitm().
static void test_relay_validation(void) {
    struct blerp_attack_config cfg;
    struct blerp_relay_report rep;

    // No target: it is both the connection target and the fake-Peripheral
    // spoofed identity, so the relay cannot proceed without it.
    blerp_config_init(&cfg, BLERP_ATTACK_MITM);
    CHECK(blerp_run_single_channel_mitm(&cfg, &rep) == -1);

    // Same adapter given twice: the two links each need their own adapter.
    blerp_config_init(&cfg, BLERP_ATTACK_MITM);
    memset(cfg.target_addr, 0xAB, sizeof cfg.target_addr);
    cfg.dev_id = 0;
    cfg.dev_id_sec = 0;
    CHECK(blerp_run_single_channel_mitm(&cfg, &rep) == -1);

    // NULL arguments are rejected like every other blerp_run_* entry point.
    CHECK(blerp_run_single_channel_mitm(NULL, &rep) == -1);
    CHECK(blerp_run_single_channel_mitm(&cfg, NULL) == -1);
}

int main(void) {
    printf("test_blerp_mitm_relay\n");
    test_should_rewrite();
    test_relay_validation();
    return TEST_REPORT();
}
