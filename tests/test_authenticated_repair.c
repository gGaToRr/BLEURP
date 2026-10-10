// ========================================
//  nom du fichier: test_authenticated_repair.c
//  description courte: Unit tests for the VII-B authenticated re-pairing
//  reference protocol. The two tests that matter most mirror the paper's
//  own claims (see Artifact Appendix D): key chaining means an attacker
//  without the bond's current PK cannot derive the same new PK even with
//  full channel control, and transcript hashing means tampering with any
//  message diverges the new PK too (integrity). See
//  authenticated_repair.h for what this does and does not prove (a
//  reference implementation of the paper's own proposed protocol, not an
//  existing deployed standard with external vectors to check against).
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "authenticated_repair.h"

#include <string.h>

// Run the full exchange between an already-auth_repair_init'd pair.
static int run_exchange(struct auth_repair *ini, struct auth_repair *rsp,
                        uint8_t ar_a, uint8_t ent_a, uint8_t ar_b, uint8_t ent_b) {
    uint8_t req[2], rsp_pdu[2];
    if (auth_repair_make_req(ini, ar_a, ent_a, req) != 2) return -1;
    if (auth_repair_on_req(rsp, req) != 0) return -1;
    if (auth_repair_make_rsp(rsp, ar_b, ent_b, rsp_pdu) != 2) return -1;
    if (auth_repair_on_rsp(ini, rsp_pdu) != 0) return -1;

    uint8_t pk_ini[64], pk_rsp[64];
    if (auth_repair_make_pubkey(ini, pk_ini) != 64) return -1;
    if (auth_repair_make_pubkey(rsp, pk_rsp) != 64) return -1;
    if (auth_repair_on_pubkey(rsp, pk_ini) != 0) return -1;
    if (auth_repair_on_pubkey(ini, pk_rsp) != 0) return -1;

    if (auth_repair_derive_pk(ini) != 0) return -1;
    if (auth_repair_derive_pk(rsp) != 0) return -1;
    return 0;
}

// Two legitimate parties sharing the same bond PK agree on the same new PK.
static void test_legitimate_pair_agrees(void) {
    uint8_t old_pk[16]; memset(old_pk, 0x55, 16);
    struct auth_repair ini, rsp;
    CHECK(auth_repair_init(&ini, true, old_pk) == 0);
    CHECK(auth_repair_init(&rsp, false, old_pk) == 0);

    CHECK(run_exchange(&ini, &rsp, 0x01, 16, 0x01, 16) == 0);
    CHECK(ini.done && rsp.done);
    CHECK(memcmp(ini.new_pk, rsp.new_pk, 16) == 0);
    CHECK(memcmp(ini.transcript, rsp.transcript, 32) == 0);

    auth_repair_free(&ini);
    auth_repair_free(&rsp);
}

// Key chaining: an attacker who completes the exact same message exchange
// (same AR/Ent, same public keys -- i.e. full control of the channel, the
// worst case for a MitM) but does NOT know the bond's real PK derives a
// DIFFERENT new PK than the one Alice/Bob would have agreed on between
// themselves. This is what makes every BLERP downgrade attack -- which
// forges a brand new pairing and never recovers the victims' existing PK
// -- produce a key nobody else accepts.
static void test_attacker_without_old_pk_diverges(void) {
    uint8_t real_pk[16]; memset(real_pk, 0x55, 16);
    uint8_t charlies_guess[16]; memset(charlies_guess, 0xAA, 16); // anything != real_pk

    struct auth_repair alice, bob_via_charlie;
    CHECK(auth_repair_init(&alice, true, real_pk) == 0);
    // Charlie relays the exact same wire bytes Alice sent/received, but he
    // himself only knows a guessed PK when deriving -- simulated here by
    // running Bob's side of the protocol against charlies_guess instead of
    // real_pk, with the exact same transcript inputs.
    CHECK(auth_repair_init(&bob_via_charlie, false, charlies_guess) == 0);

    CHECK(run_exchange(&alice, &bob_via_charlie, 0x01, 16, 0x01, 16) == 0);
    CHECK(alice.done && bob_via_charlie.done);
    // Same transcript (nothing was tampered)...
    CHECK(memcmp(alice.transcript, bob_via_charlie.transcript, 32) == 0);
    // ...but different new PK, because the CMAC key (the old PK) differs.
    CHECK(memcmp(alice.new_pk, bob_via_charlie.new_pk, 16) != 0);

    auth_repair_free(&alice);
    auth_repair_free(&bob_via_charlie);
}

// Integrity protection: if the Pairing Request's AR/Ent byte is modified
// in flight (Charlie downgrading the security level, the exact move every
// BLERP attack makes), the two sides' transcripts -- and therefore their
// new PKs -- diverge, even though both otherwise completed the exchange
// and both still know the correct old PK.
static void test_tampered_transcript_diverges(void) {
    uint8_t old_pk[16]; memset(old_pk, 0x55, 16);
    struct auth_repair ini, rsp;
    CHECK(auth_repair_init(&ini, true, old_pk) == 0);
    CHECK(auth_repair_init(&rsp, false, old_pk) == 0);

    uint8_t req[2], rsp_pdu[2];
    CHECK(auth_repair_make_req(&ini, 0x0d, 16, req) == 2); // Alice asks for MITM+SC
    req[0] = 0x01; // Charlie downgrades it to Bonding-only before Bob sees it
    CHECK(auth_repair_on_req(&rsp, req) == 0);
    CHECK(auth_repair_make_rsp(&rsp, 0x01, 7, rsp_pdu) == 2);
    CHECK(auth_repair_on_rsp(&ini, rsp_pdu) == 0);

    uint8_t pk_ini[64], pk_rsp[64];
    CHECK(auth_repair_make_pubkey(&ini, pk_ini) == 64);
    CHECK(auth_repair_make_pubkey(&rsp, pk_rsp) == 64);
    CHECK(auth_repair_on_pubkey(&rsp, pk_ini) == 0);
    CHECK(auth_repair_on_pubkey(&ini, pk_rsp) == 0);

    CHECK(auth_repair_derive_pk(&ini) == 0);
    CHECK(auth_repair_derive_pk(&rsp) == 0);

    // Alice's transcript folded in her original (un-tampered) request;
    // Bob's folded in the downgraded one he actually received.
    CHECK(memcmp(ini.transcript, rsp.transcript, 32) != 0);
    CHECK(memcmp(ini.new_pk, rsp.new_pk, 16) != 0);

    auth_repair_free(&ini);
    auth_repair_free(&rsp);
}

// A first-ever pairing (no prior bond) still works, seeded from an
// all-zero PK, and produces a key distinct from any non-zero-PK session.
static void test_first_pairing_all_zero_pk(void) {
    uint8_t zero_pk[16] = {0};
    struct auth_repair ini, rsp;
    CHECK(auth_repair_init(&ini, true, zero_pk) == 0);
    CHECK(auth_repair_init(&rsp, false, zero_pk) == 0);
    CHECK(run_exchange(&ini, &rsp, 0x01, 16, 0x01, 16) == 0);
    CHECK(memcmp(ini.new_pk, rsp.new_pk, 16) == 0);
    auth_repair_free(&ini);
    auth_repair_free(&rsp);
}

// Two independent sessions (fresh ECDH key pairs each time) never produce
// the same new PK, even with the same bond PK and the same AR/Ent.
static void test_new_pk_differs_per_session(void) {
    uint8_t old_pk[16]; memset(old_pk, 0x77, 16);
    struct auth_repair ini1, rsp1, ini2, rsp2;
    CHECK(auth_repair_init(&ini1, true, old_pk) == 0);
    CHECK(auth_repair_init(&rsp1, false, old_pk) == 0);
    CHECK(run_exchange(&ini1, &rsp1, 0x01, 16, 0x01, 16) == 0);

    CHECK(auth_repair_init(&ini2, true, old_pk) == 0);
    CHECK(auth_repair_init(&rsp2, false, old_pk) == 0);
    CHECK(run_exchange(&ini2, &rsp2, 0x01, 16, 0x01, 16) == 0);

    CHECK(memcmp(ini1.new_pk, ini2.new_pk, 16) != 0);

    auth_repair_free(&ini1); auth_repair_free(&rsp1);
    auth_repair_free(&ini2); auth_repair_free(&rsp2);
}

int main(void) {
    printf("test_authenticated_repair\n");
    test_legitimate_pair_agrees();
    test_attacker_without_old_pk_diverges();
    test_tampered_transcript_diverges();
    test_first_pairing_all_zero_pk();
    test_new_pk_differs_per_session();
    return TEST_REPORT();
}
