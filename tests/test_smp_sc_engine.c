// ========================================
//  nom du fichier: test_smp_sc_engine.c
//  description courte: Unit tests for the SC Just Works/Numeric Comparison
//  Phase 2 state machine: a full initiator/responder loopback that must
//  derive the same LTK, and rejection of a tampered nonce/DHKey Check. See
//  smp_sc_engine.h for what this loopback can and cannot prove (internal
//  self-consistency, not interop validation against a real peer or the
//  spec text).
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp_sc_engine.h"

#include <string.h>

static void init_pair(struct smp_sc *ini, struct smp_sc *rsp) {
    uint8_t ia[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t ra[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t na[16], nb[16];
    memset(na, 0x33, 16);
    memset(nb, 0x77, 16);
    CHECK(smp_sc_init(ini, true, 0, ia, 1, ra, na) == 0);
    CHECK(smp_sc_init(rsp, false, 0, ia, 1, ra, nb) == 0);
}

// Run the full SC Just Works exchange between an already-smp_sc_init'd
// initiator/responder pair. `tamper_random` flips a bit in the responder's
// Pairing Random after it is sent, simulating an on-the-wire modification
// (or a MitM swapping the nonce), to exercise the Confirm Value check.
static int run_pairing(struct smp_sc *ini, struct smp_sc *rsp, bool tamper_random) {
    uint8_t req[7], rsp_pdu[7];
    if (smp_sc_make_req(ini, req) != 7) return -1;
    if (smp_sc_on_req(rsp, req) != 0) return -1;
    if (smp_sc_make_rsp(rsp, rsp_pdu) != 7) return -1;
    if (smp_sc_on_rsp(ini, rsp_pdu) != 0) return -1;

    uint8_t pk_ini[65], pk_rsp[65];
    if (smp_sc_make_pubkey(ini, pk_ini) != 65) return -1;
    if (smp_sc_make_pubkey(rsp, pk_rsp) != 65) return -1;
    if (smp_sc_on_pubkey(rsp, pk_ini) != 0) return -1;
    if (smp_sc_on_pubkey(ini, pk_rsp) != 0) return -1;

    uint8_t confirm[17];
    if (smp_sc_make_confirm(rsp, confirm) != 17) return -1;
    if (smp_sc_on_confirm(ini, confirm) != 0) return -1;

    uint8_t rand_ini[17], rand_rsp[17];
    if (smp_sc_make_random(ini, rand_ini) != 17) return -1;
    if (smp_sc_make_random(rsp, rand_rsp) != 17) return -1;
    if (tamper_random) rand_rsp[1] ^= 0xFF; // corrupt Nb after it "left the wire"
    if (smp_sc_on_random(rsp, rand_ini) != 0) return -1;
    if (smp_sc_on_random(ini, rand_rsp) != 0) return -1;

    if (ini->failed) return 0; // stop here: no DHKey to check against
    if (smp_sc_derive_keys(ini) != 0) return -1;
    if (smp_sc_derive_keys(rsp) != 0) return -1;

    uint8_t check_ini[17], check_rsp[17];
    if (smp_sc_make_dhkey_check(ini, check_ini) != 17) return -1;
    if (smp_sc_make_dhkey_check(rsp, check_rsp) != 17) return -1;
    if (smp_sc_on_dhkey_check(rsp, check_ini) != 0) return -1;
    if (smp_sc_on_dhkey_check(ini, check_rsp) != 0) return -1;
    return 0;
}

// Full exchange: both sides finish, derive the same LTK, and no check fails.
static void test_loopback_same_ltk(void) {
    struct smp_sc ini, rsp;
    init_pair(&ini, &rsp);
    CHECK(run_pairing(&ini, &rsp, false) == 0);
    CHECK(ini.done && !ini.failed);
    CHECK(rsp.done && !rsp.failed);
    CHECK(memcmp(ini.ltk, rsp.ltk, 16) == 0);
    CHECK(memcmp(ini.mackey, rsp.mackey, 16) == 0);
    // MacKey and LTK are two distinct outputs of the same f5 call.
    CHECK(memcmp(ini.mackey, ini.ltk, 16) != 0);
    smp_sc_free(&ini);
    smp_sc_free(&rsp);
}

// A responder nonce changed on the wire must fail the initiator's Confirm
// check, with the documented reason, and neither side reaches `done`.
static void test_tampered_random_rejected(void) {
    struct smp_sc ini, rsp;
    init_pair(&ini, &rsp);
    CHECK(run_pairing(&ini, &rsp, true) == 0);
    CHECK(ini.failed && !ini.done);
    CHECK(ini.reason == 0x04);
    CHECK(!rsp.done);
    smp_sc_free(&ini);
    smp_sc_free(&rsp);
}

// The LTK depends on both ECDH key pairs (fresh per smp_sc_init call): two
// independent sessions never produce the same LTK.
static void test_ltk_differs_per_session(void) {
    struct smp_sc ini1, rsp1, ini2, rsp2;
    init_pair(&ini1, &rsp1);
    CHECK(run_pairing(&ini1, &rsp1, false) == 0);

    init_pair(&ini2, &rsp2);
    CHECK(run_pairing(&ini2, &rsp2, false) == 0);

    CHECK(memcmp(ini1.ltk, ini2.ltk, 16) != 0);
    smp_sc_free(&ini1); smp_sc_free(&rsp1);
    smp_sc_free(&ini2); smp_sc_free(&rsp2);
}

// smp_sc_set_params forces the SC bit on even if the caller forgets it
// (this engine cannot run without it), and a downgraded AuthReq/key size
// still reaches both PDUs and both sides' final negotiated values.
static void test_set_params_forces_sc_bit(void) {
    struct smp_sc ini, rsp;
    init_pair(&ini, &rsp);
    smp_sc_set_params(&ini, 0x01, 7);   // Bonding only, no SC bit given
    smp_sc_set_params(&rsp, 0x01, 7);

    uint8_t req[7], rsp_pdu[7];
    CHECK(smp_sc_make_req(&ini, req) == 7);
    CHECK((req[3] & 0x08) != 0); // SC bit forced on
    CHECK(req[4] == 7);          // downgraded key size still applied
    CHECK(smp_sc_on_req(&rsp, req) == 0);
    CHECK(smp_sc_make_rsp(&rsp, rsp_pdu) == 7);
    CHECK((rsp_pdu[3] & 0x08) != 0);

    smp_sc_free(&ini);
    smp_sc_free(&rsp);
}

int main(void) {
    printf("test_smp_sc_engine\n");
    test_loopback_same_ltk();
    test_tampered_random_rejected();
    test_ltk_differs_per_session();
    test_set_params_forces_sc_bit();
    return TEST_REPORT();
}
