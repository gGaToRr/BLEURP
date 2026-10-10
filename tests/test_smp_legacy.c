// ========================================
//  nom du fichier: test_smp_legacy.c
//  description courte: Unit tests for legacy Just Works pairing: c1/s1 against
//  the Core spec sample values (reconstructed from memory, see below), a full
//  initiator/responder loopback that must derive the same STK, and the
//  rejection of a tampered confirm value.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp_legacy.h"

#include <string.h>

// Big-endian hex (as the spec prints it) to the little-endian array the PDUs use.
static void be_to_le(const char *hex, uint8_t out[16]) {
    for (int i = 0; i < 16; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[15 - i] = (uint8_t)v;
    }
}

// s1 sample from Core Vol 3 Part H, D.3: k = 0, r1 = 000F0E0D..77 88,
// r2 = 01020304..99AABBCCDDEEFF00, expected STK 9a1fe1f0e8b0f49b5b4216ae796da062.
static void test_s1_spec_sample(void) {
    uint8_t k[16] = {0}, r1[16], r2[16], want[16], got[16];
    be_to_le("000f0e0d0c0b0a091122334455667788", r1);
    be_to_le("0102030405060708" "99aabbccddeeff00", r2);
    be_to_le("9a1fe1f0e8b0f49b5b4216ae796da062", want);
    // s1(k, r1, r2): r2 supplies the first 8 bytes of r', r1 the last 8.
    CHECK(smp_legacy_s1(k, r2, r1, got) == 0);
    CHECK(memcmp(got, want, 16) == 0);
}

// Seven displayed big-endian bytes to the PDU-order array.
static void be_to_le7(const char *hex, uint8_t out[7]) {
    for (int i = 0; i < 7; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[6 - i] = (uint8_t)v;
    }
}

// c1 sample from Core Vol 3 Part H, D.1, reconstructed from memory:
// k = 0, r = 5783d52156ad6f0e6388274ec6702ee0, pres = 05000800000302,
// preq = 07071000000101, iat = 1, ia = a1a2a3a4a5a6, rat = 0, ra = b1b2b3b4b5b6,
// expected c1 = 1e1e3fef878988ead2a74dc5bef13b86. Every value is printed
// big-endian, so pres and preq are reversed into their PDU order too.
static void test_c1_spec_sample(void) {
    uint8_t k[16] = {0}, r[16], want[16], got[16];
    uint8_t pres[7], preq[7];
    be_to_le7("05000800000302", pres);
    be_to_le7("07071000000101", preq);
    uint8_t ia[6] = {0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1};
    uint8_t ra[6] = {0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1};
    be_to_le("5783d52156ad6f0e6388274ec6702ee0", r);
    be_to_le("1e1e3fef878988ead2a74dc5bef13b86", want);
    CHECK(smp_legacy_c1(k, r, preq, pres, 1, ia, 0, ra, got) == 0);
    CHECK(memcmp(got, want, 16) == 0);
}

// Run both sides in memory, in the order of the standard. Returns the number
// of steps that failed to build or read.
static int run_pairing(struct smp_legacy *ini, struct smp_legacy *rsp,
                       bool tamper_random) {
    uint8_t p7[7], p17[17];
    int errs = 0;

    errs += smp_legacy_make_req(ini, p7) != 7;
    errs += smp_legacy_on_req(rsp, p7) != 0;
    errs += smp_legacy_make_rsp(rsp, p7) != 7;
    errs += smp_legacy_on_rsp(ini, p7) != 0;

    errs += smp_legacy_make_confirm(ini, p17) != 17;   // Mconfirm
    errs += smp_legacy_on_confirm(rsp, p17) != 0;
    errs += smp_legacy_make_confirm(rsp, p17) != 17;   // Sconfirm
    errs += smp_legacy_on_confirm(ini, p17) != 0;

    errs += smp_legacy_make_random(ini, p17) != 17;    // Mrand
    errs += smp_legacy_on_random(rsp, p17) != 0;
    errs += smp_legacy_make_random(rsp, p17) != 17;    // Srand
    if (tamper_random) p17[5] ^= 0x01;
    errs += smp_legacy_on_random(ini, p17) != 0;
    return errs;
}

static void init_pair(struct smp_legacy *ini, struct smp_legacy *rsp) {
    const uint8_t ia[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    const uint8_t ra[6] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t ri[16], rr[16];
    for (int i = 0; i < 16; i++) {
        ri[i] = (uint8_t)(0x30 + i);
        rr[i] = (uint8_t)(0x90 + 3 * i);
    }
    smp_legacy_init(ini, true, 0, ia, 0, ra, ri);
    smp_legacy_init(rsp, false, 0, ia, 0, ra, rr);
}

// Full exchange: both sides finish, derive the same STK, and no check fails.
static void test_loopback_same_stk(void) {
    struct smp_legacy ini, rsp;
    init_pair(&ini, &rsp);
    CHECK(run_pairing(&ini, &rsp, false) == 0);
    CHECK(ini.done && !ini.failed);
    CHECK(rsp.done && !rsp.failed);
    CHECK(memcmp(ini.stk, rsp.stk, 16) == 0);
}

// A random changed on the wire must fail the confirm check on the initiator,
// with the Confirm Value Failed reason, and no STK.
static void test_tampered_random_rejected(void) {
    struct smp_legacy ini, rsp;
    init_pair(&ini, &rsp);
    CHECK(run_pairing(&ini, &rsp, true) == 0);
    CHECK(ini.failed && !ini.done);
    CHECK(ini.reason == 0x04);
}

// The STK depends on both randoms: a different responder random gives another key.
static void test_stk_depends_on_randoms(void) {
    struct smp_legacy a, b, c;
    init_pair(&a, &b);
    CHECK(run_pairing(&a, &b, false) == 0);

    struct smp_legacy ini2, rsp2;
    init_pair(&ini2, &rsp2);
    uint8_t other[16];
    memset(other, 0x42, 16);
    smp_legacy_init(&rsp2, false, 0, ini2.ia, 0, ini2.ra, other);
    CHECK(run_pairing(&ini2, &rsp2, false) == 0);
    CHECK(memcmp(a.stk, ini2.stk, 16) != 0);
    (void)c;
}

int main(void) {
    printf("test_smp_legacy\n");
    test_s1_spec_sample();
    test_c1_spec_sample();
    test_loopback_same_stk();
    test_tampered_random_rejected();
    test_stk_depends_on_randoms();
    return TEST_REPORT();
}
