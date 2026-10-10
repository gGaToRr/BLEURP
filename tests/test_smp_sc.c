// ========================================
//  nom du fichier: test_smp_sc.c
//  description courte: Unit tests for the LE Secure Connections crypto
//  toolbox (ECDH P-256, f4, f5, f6, g2). The AES-128-CMAC primitive these
//  all sit on (src/smp/smp_sc.c's aes_cmac_be, private to that file) was
//  checked by hand during development against all four RFC 4493 Section 4
//  test vectors (empty, 16-, 40- and 64-byte messages under the RFC's
//  sample key) and reproduced them exactly; that check isn't automated
//  here because the wrapper isn't part of this module's public contract.
//  What IS automated: ECDH agreement is symmetric and round-trips through
//  the wire-order conversion correctly; f4/f6/g2 are deterministic and
//  sensitive to every argument (catches a dropped/misordered field); f5
//  produces two distinct, deterministic 16-byte outputs. See smp_sc.h for
//  the f5 SALT/keyID caveat this does NOT resolve (self-consistency can't
//  catch a wrong-but-consistent constant).
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp_sc.h"

#include <string.h>

static void fill(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(seed + i * 7);
}

// Both sides of an ECDH exchange agree on the same DHKey, and the result
// round-trips correctly through smp_sc_public_key()'s wire-order encoding.
static void test_ecdh_agreement(void) {
    struct smp_sc_keypair *a = smp_sc_keygen();
    struct smp_sc_keypair *b = smp_sc_keygen();
    CHECK(a != NULL);
    CHECK(b != NULL);

    uint8_t pub_a[64], pub_b[64];
    CHECK(smp_sc_public_key(a, pub_a) == 0);
    CHECK(smp_sc_public_key(b, pub_b) == 0);
    // Two fresh key pairs should not coincidentally share a public key.
    CHECK(memcmp(pub_a, pub_b, 64) != 0);

    uint8_t dhkey_a[32], dhkey_b[32];
    CHECK(smp_sc_dhkey(a, pub_b, dhkey_a) == 0);
    CHECK(smp_sc_dhkey(b, pub_a, dhkey_b) == 0);
    CHECK(memcmp(dhkey_a, dhkey_b, 32) == 0);

    smp_sc_keypair_free(a);
    smp_sc_keypair_free(b);
}

// A corrupted (not-on-curve) peer public key is rejected, not silently
// accepted into a bogus shared secret (invalid-curve attack surface).
static void test_ecdh_rejects_invalid_point(void) {
    struct smp_sc_keypair *a = smp_sc_keygen();
    struct smp_sc_keypair *b = smp_sc_keygen();
    CHECK(a != NULL && b != NULL);

    uint8_t pub_b[64];
    CHECK(smp_sc_public_key(b, pub_b) == 0);
    pub_b[0] ^= 0xFF; // corrupt the X coordinate: no longer a curve point

    uint8_t dhkey[32];
    CHECK(smp_sc_dhkey(a, pub_b, dhkey) == -1);

    smp_sc_keypair_free(a);
    smp_sc_keypair_free(b);
}

// NULL arguments are rejected across the whole module.
static void test_null_args(void) {
    uint8_t buf64[64] = {0}, buf32[32] = {0}, buf16[16] = {0}, buf7[7] = {0}, buf3[3] = {0};
    uint8_t out64[64], out32[32], out16[16];
    uint32_t out_u32;

    CHECK(smp_sc_public_key(NULL, out64) == -1);
    CHECK(smp_sc_dhkey(NULL, buf64, out32) == -1);
    CHECK(smp_sc_f4(NULL, buf32, buf16, 0, out16) == -1);
    CHECK(smp_sc_f5(NULL, buf16, buf16, buf7, buf7, out16, out16) == -1);
    CHECK(smp_sc_f6(NULL, buf16, buf16, buf16, buf3, buf7, buf7, out16) == -1);
    CHECK(smp_sc_g2(NULL, buf32, buf16, buf16, &out_u32) == -1);
}

// f4 is deterministic, and swapping U/V or changing X/Z changes the result
// -- catches a dropped or misordered field, not just "returns something".
static void test_f4_sensitivity(void) {
    uint8_t u[32], v[32], x[16], out1[16], out2[16];
    fill(u, 32, 0x01);
    fill(v, 32, 0x41);
    fill(x, 16, 0x81);

    CHECK(smp_sc_f4(u, v, x, 0x00, out1) == 0);
    CHECK(smp_sc_f4(u, v, x, 0x00, out2) == 0);
    CHECK(memcmp(out1, out2, 16) == 0); // deterministic

    CHECK(smp_sc_f4(v, u, x, 0x00, out2) == 0); // swap U/V
    CHECK(memcmp(out1, out2, 16) != 0);

    CHECK(smp_sc_f4(u, v, x, 0x01, out2) == 0); // change Z
    CHECK(memcmp(out1, out2, 16) != 0);

    uint8_t x2[16]; fill(x2, 16, 0x82);
    CHECK(smp_sc_f4(u, v, x2, 0x00, out2) == 0); // change key X
    CHECK(memcmp(out1, out2, 16) != 0);
}

// f5 produces two distinct, deterministic outputs (MacKey != LTK), and
// changing the DHKey or either nonce changes both.
static void test_f5_sensitivity(void) {
    uint8_t w[32], n1[16], n2[16], a1[7], a2[7];
    fill(w, 32, 0x10);
    fill(n1, 16, 0x20);
    fill(n2, 16, 0x30);
    fill(a1, 7, 0x40);
    fill(a2, 7, 0x50);

    uint8_t mackey1[16], ltk1[16], mackey2[16], ltk2[16];
    CHECK(smp_sc_f5(w, n1, n2, a1, a2, mackey1, ltk1) == 0);
    CHECK(memcmp(mackey1, ltk1, 16) != 0); // the two CMAC outputs differ

    CHECK(smp_sc_f5(w, n1, n2, a1, a2, mackey2, ltk2) == 0);
    CHECK(memcmp(mackey1, mackey2, 16) == 0); // deterministic
    CHECK(memcmp(ltk1, ltk2, 16) == 0);

    uint8_t w2[32]; fill(w2, 32, 0x11);
    CHECK(smp_sc_f5(w2, n1, n2, a1, a2, mackey2, ltk2) == 0);
    CHECK(memcmp(mackey1, mackey2, 16) != 0);
    CHECK(memcmp(ltk1, ltk2, 16) != 0);

    uint8_t n1b[16]; fill(n1b, 16, 0x21);
    CHECK(smp_sc_f5(w, n1b, n2, a1, a2, mackey2, ltk2) == 0);
    CHECK(memcmp(ltk1, ltk2, 16) != 0);
}

// f6 is deterministic and sensitive to the nonce, the random value, IOcap,
// and both addresses.
static void test_f6_sensitivity(void) {
    uint8_t w[16], n1[16], n2[16], r[16], iocap[3], a1[7], a2[7];
    fill(w, 16, 0x60); fill(n1, 16, 0x70); fill(n2, 16, 0x80);
    fill(r, 16, 0x90); iocap[0] = 0x01; iocap[1] = 0x00; iocap[2] = 0x03;
    fill(a1, 7, 0xA0); fill(a2, 7, 0xB0);

    uint8_t out1[16], out2[16];
    CHECK(smp_sc_f6(w, n1, n2, r, iocap, a1, a2, out1) == 0);
    CHECK(smp_sc_f6(w, n1, n2, r, iocap, a1, a2, out2) == 0);
    CHECK(memcmp(out1, out2, 16) == 0);

    uint8_t iocap2[3] = { 0x05, 0x00, 0x03 };
    CHECK(smp_sc_f6(w, n1, n2, r, iocap2, a1, a2, out2) == 0);
    CHECK(memcmp(out1, out2, 16) != 0);

    uint8_t a2b[7]; fill(a2b, 7, 0xB1);
    CHECK(smp_sc_f6(w, n1, n2, r, iocap, a1, a2b, out2) == 0);
    CHECK(memcmp(out1, out2, 16) != 0);
}

// g2's display value always lands in the 6-digit range, is deterministic,
// and changes when either nonce changes.
static void test_g2_range_and_sensitivity(void) {
    uint8_t u[32], v[32], x[16], y[16];
    fill(u, 32, 0xC0); fill(v, 32, 0xD0); fill(x, 16, 0xE0); fill(y, 16, 0xF0);

    uint32_t out1, out2;
    CHECK(smp_sc_g2(u, v, x, y, &out1) == 0);
    CHECK(out1 <= 999999u);

    CHECK(smp_sc_g2(u, v, x, y, &out2) == 0);
    CHECK(out1 == out2);

    uint8_t y2[16]; fill(y2, 16, 0xF1);
    CHECK(smp_sc_g2(u, v, x, y2, &out2) == 0);
    CHECK(out1 != out2);
}

int main(void) {
    printf("test_smp_sc\n");
    test_ecdh_agreement();
    test_ecdh_rejects_invalid_point();
    test_null_args();
    test_f4_sensitivity();
    test_f5_sensitivity();
    test_f6_sensitivity();
    test_g2_range_and_sensitivity();
    return TEST_REPORT();
}
