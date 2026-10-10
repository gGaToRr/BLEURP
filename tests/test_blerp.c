// ========================================
//  nom du fichier: test_blerp.c
//  description courte: Unit tests for BLERP native attack primitives (NDSS 2026).
//  Tests advertising data builder, PDU rewriters, V1-V6 classification,
//  and PI/CI simulated handshake loopback. Pure: no I/O, no root required.
//  dernière modification : 2026-10-04
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "blerp_attack.h"

#include <string.h>

// Verify advertising data generation with flags, name and appearance.
static void test_adv_data_builder(void) {
    uint8_t buf[64];
    size_t len = blerp_build_adv_data("TestDevice", 0x03C1, buf, sizeof buf);
    CHECK(len > 0);

    // Flags: len=2, type=0x01, val=0x06
    CHECK(buf[0] == 0x02 && buf[1] == 0x01 && buf[2] == 0x06);

    // Appearance: len=3, type=0x19, val=0xC1, 0x03
    CHECK(buf[3] == 0x03 && buf[4] == 0x19 && buf[5] == 0xC1 && buf[6] == 0x03);

    // Complete Local Name: len=11, type=0x09, "TestDevice"
    CHECK(buf[7] == 11 && buf[8] == 0x09);
    CHECK(memcmp(&buf[9], "TestDevice", 10) == 0);

    // Buffer too small should return 0 safely
    uint8_t tiny[2];
    CHECK(blerp_build_adv_data("TooSmall", 0x03C1, tiny, sizeof tiny) == 0);
}

// Verify SMP Pairing Request rewriting for parameter downgrade.
static void test_pdu_preq_rewriter(void) {
    // Normal Pairing Request: AuthReq = 0x0d (Bonding|MITM|SC), KeySize = 16
    uint8_t preq[7] = { 0x01, 0x03, 0x00, 0x0d, 0x10, 0x01, 0x01 };
    uint8_t out[7];

    // Force AuthReq = 0x01 (Bonding only) and KeySize = 7
    CHECK(blerp_rewrite_preq(preq, out, 0x01, 7) == 7);
    CHECK(out[0] == 0x01); // Opcode unchanged
    CHECK(out[1] == 0x03); // IOCap unchanged
    CHECK(out[3] == 0x01); // AuthReq downgraded
    CHECK(out[4] == 7);    // KeySize clamped to 7

    // Invalid opcode rejection
    uint8_t invalid[7] = { 0x02, 0, 0, 0, 0, 0, 0 };
    CHECK(blerp_rewrite_preq(invalid, out, 0x01, 7) == -1);
}

// Verify SMP Pairing Response rewriting for parameter downgrade.
static void test_pdu_pres_rewriter(void) {
    uint8_t pres[7] = { 0x02, 0x01, 0x00, 0x0d, 0x10, 0x01, 0x01 };
    uint8_t out[7];

    CHECK(blerp_rewrite_pres(pres, out, 0x01, 7) == 7);
    CHECK(out[0] == 0x02);
    CHECK(out[3] == 0x01);
    CHECK(out[4] == 7);

    uint8_t invalid[7] = { 0x01, 0, 0, 0, 0, 0, 0 };
    CHECK(blerp_rewrite_pres(invalid, out, 0x01, 7) == -1);
}

// Test V1: Central accepting an unauthenticated Security Request.
static void test_v1_unauth_secreq(void) {
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.secreq_sent = true;
    raw.preq_received = true; // Central reacted with pairing
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V1_UNAUTH_SECREQ] == BLERP_VERDICT_YES);

    raw.preq_received = false; // Central ignored
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V1_UNAUTH_SECREQ] == BLERP_VERDICT_NO);
}

// Test V2: Peripheral accepting an unauthenticated Pairing Request on an existing bond.
static void test_v2_unauth_repair(void) {
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.preq_sent = true;
    raw.pres_received = true; // Peripheral accepted
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_YES);

    raw.pres_received = false;
    raw.pairing_failed = true;
    raw.fail_reason = 0x05;
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_NO);
}

// Test V3: Downgrade acceptance in Phase 2.
static void test_v3_peripheral_downgrade(void) {
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.preq_received = true;
    raw.pres_sent = true;
    raw.phase2_completed = true;
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE] == BLERP_VERDICT_YES);

    raw.phase2_completed = false;
    raw.pairing_failed = true;
    raw.fail_reason = 0x03; // Authentication requirements error
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE] == BLERP_VERDICT_NO);
}

// Test V4: Re-pairing level downgrade below authenticated bond (ARPK).
static void test_v4_level_downgrade(void) {
    struct smp_bond_info auth_bond = { .authenticated = true, .enc_size = 16 };
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.phase2_completed = true;
    raw.negotiated_authreq = 0x01; // MITM bit (0x04) dropped!
    blerp_classify_vulnerabilities(&auth_bond, &raw, &out);
    CHECK(out.verdicts[BLERP_V4_LEVEL_DOWNGRADE] == BLERP_VERDICT_YES);

    raw.negotiated_authreq = 0x05; // MITM bit preserved
    blerp_classify_vulnerabilities(&auth_bond, &raw, &out);
    CHECK(out.verdicts[BLERP_V4_LEVEL_DOWNGRADE] == BLERP_VERDICT_NO);
}

// Test V5: Session break / encryption rejection triggering re-pairing.
static void test_v5_session_break(void) {
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.enc_rejected = true;
    raw.preq_received = true; // Central launched re-pairing
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V5_SESSION_BREAK] == BLERP_VERDICT_YES);

    raw.preq_received = false; // Central disconnected without re-pairing
    blerp_classify_vulnerabilities(NULL, &raw, &out);
    CHECK(out.verdicts[BLERP_V5_SESSION_BREAK] == BLERP_VERDICT_NO);
}

// Test V6: Key entropy reduction below stored bond.
static void test_v6_entropy_downgrade(void) {
    struct smp_bond_info bond16 = { .authenticated = true, .enc_size = 16 };
    struct blerp_attack_report raw;
    struct blerp_attack_report out;
    memset(&raw, 0, sizeof raw);

    raw.connected = true;
    raw.phase2_completed = true;
    raw.negotiated_keysize = 7; // Downgraded to 7 bytes
    blerp_classify_vulnerabilities(&bond16, &raw, &out);
    CHECK(out.verdicts[BLERP_V6_ENTROPY_DOWNGRADE] == BLERP_VERDICT_YES);

    raw.negotiated_keysize = 16; // Kept 16 bytes
    blerp_classify_vulnerabilities(&bond16, &raw, &out);
    CHECK(out.verdicts[BLERP_V6_ENTROPY_DOWNGRADE] == BLERP_VERDICT_NO);
}

// Simulated end-to-end handshake between PI (Peripheral) and CI (Central)
// verifying that custom downgraded parameters yield identical derived STKs.
static void test_pi_ci_handshake_loopback(void) {
    struct smp_legacy ini, rsp;
    const uint8_t ia[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const uint8_t ra[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint8_t rand_ini[16], rand_rsp[16];
    memset(rand_ini, 0x33, 16);
    memset(rand_rsp, 0x77, 16);

    smp_legacy_init(&ini, true, 0, ia, 1, ra, rand_ini);
    smp_legacy_init(&rsp, false, 0, ia, 1, ra, rand_rsp);

    // Force downgraded parameters (AuthReq = 0x01, KeySize = 7)
    smp_legacy_set_params(&ini, 0x01, 7);
    smp_legacy_set_params(&rsp, 0x01, 7);

    uint8_t preq[7], pres[7];
    CHECK(smp_legacy_make_req(&ini, preq) == 7);
    CHECK(preq[3] == 0x01 && preq[4] == 7);
    CHECK(smp_legacy_on_req(&rsp, preq) == 0);

    CHECK(smp_legacy_make_rsp(&rsp, pres) == 7);
    CHECK(pres[3] == 0x01 && pres[4] == 7);
    CHECK(smp_legacy_on_rsp(&ini, pres) == 0);

    uint8_t mconfirm[17], sconfirm[17];
    CHECK(smp_legacy_make_confirm(&ini, mconfirm) == 17);
    CHECK(smp_legacy_on_confirm(&rsp, mconfirm) == 0);

    CHECK(smp_legacy_make_confirm(&rsp, sconfirm) == 17);
    CHECK(smp_legacy_on_confirm(&ini, sconfirm) == 0);

    uint8_t mrandom[17], srandom[17];
    CHECK(smp_legacy_make_random(&ini, mrandom) == 17);
    CHECK(smp_legacy_on_random(&rsp, mrandom) == 0);

    CHECK(smp_legacy_make_random(&rsp, srandom) == 17);
    CHECK(smp_legacy_on_random(&ini, srandom) == 0);

    CHECK(ini.done && !ini.failed);
    CHECK(rsp.done && !rsp.failed);
    CHECK(memcmp(ini.stk, rsp.stk, 16) == 0);
}

// Rating: a confirmed YES wins, a refused unauthenticated re-pairing is the
// only positive proof of protection, and nothing else is claimed.
static void test_target_rating(void) {
    enum blerp_verdict none[BLERP_VULN_COUNT];
    for (int i = 0; i < BLERP_VULN_COUNT; i++) none[i] = BLERP_VERDICT_INCONCLUSIVE;

    struct blerp_target_verdict t;
    blerp_target_verdict_init(&t);
    CHECK(blerp_target_rating(&t) == BLERP_RATING_INCONCLUSIVE);

    // Refused unauthenticated re-pairing: protected, reason kept.
    enum blerp_verdict refused[BLERP_VULN_COUNT];
    memcpy(refused, none, sizeof refused);
    refused[BLERP_V2_UNAUTH_REPAIR] = BLERP_VERDICT_NO;
    blerp_target_verdict_merge(&t, refused, 0x03);
    CHECK(blerp_target_rating(&t) == BLERP_RATING_PROTECTED);
    CHECK(t.refusal == 0x03);

    // A later run proves a level downgrade: vulnerable, whatever came before.
    enum blerp_verdict downgrade[BLERP_VULN_COUNT];
    memcpy(downgrade, none, sizeof downgrade);
    downgrade[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_YES;
    blerp_target_verdict_merge(&t, downgrade, 0);
    CHECK(blerp_target_rating(&t) == BLERP_RATING_VULNERABLE);

    // A NO never overwrites an earlier YES.
    enum blerp_verdict no_v4[BLERP_VULN_COUNT];
    memcpy(no_v4, none, sizeof no_v4);
    no_v4[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_NO;
    blerp_target_verdict_merge(&t, no_v4, 0);
    CHECK(t.v[BLERP_V4_LEVEL_DOWNGRADE] == BLERP_VERDICT_YES);

    // Only inconclusive results: nothing is claimed.
    struct blerp_target_verdict u;
    blerp_target_verdict_init(&u);
    blerp_target_verdict_merge(&u, none, 0);
    CHECK(blerp_target_rating(&u) == BLERP_RATING_INCONCLUSIVE);

    // A NO on V4 alone is not protection: V2 was never refused.
    enum blerp_verdict v4_only[BLERP_VULN_COUNT];
    memcpy(v4_only, none, sizeof v4_only);
    v4_only[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_NO;
    struct blerp_target_verdict w;
    blerp_target_verdict_init(&w);
    blerp_target_verdict_merge(&w, v4_only, 0x03);
    CHECK(blerp_target_rating(&w) == BLERP_RATING_INCONCLUSIVE);
    CHECK(w.refusal == 0x03);
}

// blerp_run_mitm must reject an unusable configuration before it ever opens
// an HCI socket, so these checks run without root or real hardware.
static void test_mitm_validation(void) {
    struct blerp_attack_config cfg;
    struct blerp_attack_report rep;

    // No target: the Peripheral address doubles as the CI connection target
    // and the PI spoofed identity, so double-channel MitM cannot proceed
    // without it.
    blerp_config_init(&cfg, BLERP_ATTACK_MITM);
    CHECK(blerp_run_mitm(&cfg, &rep) == -1);

    // Same adapter given twice: PI and CI each need their own adapter.
    blerp_config_init(&cfg, BLERP_ATTACK_MITM);
    memset(cfg.target_addr, 0xAB, sizeof cfg.target_addr);
    cfg.dev_id = 0;
    cfg.dev_id_sec = 0;
    CHECK(blerp_run_mitm(&cfg, &rep) == -1);

    // NULL arguments are rejected like every other blerp_run_* entry point.
    CHECK(blerp_run_mitm(NULL, &rep) == -1);
    CHECK(blerp_run_mitm(&cfg, NULL) == -1);
}

int main(void) {
    printf("test_blerp\n");
    test_adv_data_builder();
    test_pdu_preq_rewriter();
    test_pdu_pres_rewriter();
    test_v1_unauth_secreq();
    test_v2_unauth_repair();
    test_v3_peripheral_downgrade();
    test_v4_level_downgrade();
    test_v5_session_break();
    test_v6_entropy_downgrade();
    test_pi_ci_handshake_loopback();
    test_target_rating();
    test_mitm_validation();
    return TEST_REPORT();
}
