// ========================================
//  nom du fichier: test_secreq.c
//  description courte: Unit tests for the Security Request test (BLERP Apple
//  finding): advertising payload, ARPK estimate, expected reaction per
//  Listing 1 of the paper, and the non-conformity rule.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "secreq.h"

#include <string.h>

// Advertising payload: Flags (3 bytes) then Complete Local Name.
static void test_build_adv_name(void) {
    uint8_t buf[31];
    const uint8_t want[] = {0x02, 0x01, 0x06, 0x02, 0x09, 0x54}; // name "T"
    size_t n = secreq_build_adv("T", buf, sizeof buf);
    CHECK(n == sizeof want);
    CHECK(memcmp(buf, want, sizeof want) == 0);
}

// The payload never advertises a keyboard: no HID UUID, no keyboard appearance.
static void test_build_adv_no_hid(void) {
    uint8_t buf[31];
    size_t n = secreq_build_adv("BLEURP Test", buf, sizeof buf);
    CHECK(n > 0);
    for (size_t i = 0; i + 1 < n; i++) {
        CHECK(!(buf[i] == 0x19 && buf[i + 1] == 0xC1)); // Appearance: keyboard
        CHECK(!(buf[i] == 0x03 && buf[i + 1] == 0x03)); // 16-bit UUID list tag
    }
}

// Too small a buffer or NULL arguments give 0.
static void test_build_adv_bad_args(void) {
    uint8_t buf[31];
    CHECK(secreq_build_adv("T", buf, 5) == 0);
    CHECK(secreq_build_adv(NULL, buf, sizeof buf) == 0);
    CHECK(secreq_build_adv("T", NULL, sizeof buf) == 0);
}

// ARPK estimate: bonding bit always; MITM bit only for an authenticated bond.
static void test_arpk_guess(void) {
    struct smp_bond_info unauth = { .authenticated = false, .enc_size = 16 };
    struct smp_bond_info auth = { .authenticated = true, .enc_size = 16 };
    CHECK(secreq_arpk_guess(&unauth) == 0x01);
    CHECK(secreq_arpk_guess(&auth) == 0x05);
    CHECK(secreq_arpk_guess(NULL) == 0x01);
}

// Expected reaction (Listing 1): ARSR > ARPK means re-pairing, otherwise the
// Central starts session establishment.
static void test_expected_reaction(void) {
    CHECK(secreq_expected(0x01, 0x01) == SECREQ_SESSION_STARTED);
    CHECK(secreq_expected(0x05, 0x01) == SECREQ_PAIRING_STARTED);
    CHECK(secreq_expected(0x01, 0x05) == SECREQ_SESSION_STARTED);
}

// Observation to outcome: no link, pairing, session, or nothing.
static void test_classify(void) {
    struct secreq_observation o;

    memset(&o, 0, sizeof o);
    CHECK(secreq_classify(&o) == SECREQ_NO_LINK);

    memset(&o, 0, sizeof o);
    o.linked = true;
    CHECK(secreq_classify(&o) == SECREQ_NO_REACTION);

    memset(&o, 0, sizeof o);
    o.linked = true;
    o.pairing_request = true;
    CHECK(secreq_classify(&o) == SECREQ_PAIRING_STARTED);

    memset(&o, 0, sizeof o);
    o.linked = true;
    o.ltk_request = true;
    CHECK(secreq_classify(&o) == SECREQ_SESSION_STARTED);

    // A Pairing Request takes precedence over an LTK request.
    memset(&o, 0, sizeof o);
    o.linked = true;
    o.pairing_request = true;
    o.ltk_request = true;
    CHECK(secreq_classify(&o) == SECREQ_PAIRING_STARTED);
}

// The Apple finding: ARSR equal to ARPK must not trigger pairing.
static void test_nonconform_apple_case(void) {
    CHECK(secreq_is_nonconform(0x01, 0x01, SECREQ_PAIRING_STARTED) == true);
    CHECK(secreq_is_nonconform(0x05, 0x05, SECREQ_PAIRING_STARTED) == true);
}

// Conforming behaviours are not flagged.
static void test_conform_cases(void) {
    CHECK(secreq_is_nonconform(0x05, 0x01, SECREQ_PAIRING_STARTED) == false);
    CHECK(secreq_is_nonconform(0x01, 0x01, SECREQ_SESSION_STARTED) == false);
    CHECK(secreq_is_nonconform(0x01, 0x01, SECREQ_NO_REACTION) == false);
    CHECK(secreq_is_nonconform(0x01, 0x01, SECREQ_NO_LINK) == false);
}

// ARSR above ARPK but the Central only starts a session: also non-conform.
static void test_nonconform_session_when_higher(void) {
    CHECK(secreq_is_nonconform(0x05, 0x01, SECREQ_SESSION_STARTED) == true);
}

// V1: without a link nothing is decided; a re-pairing with rfu bits is YES,
// a Central that stays on the session path is NO.
static void test_verdict_v1(void) {
    struct secreq_observation o = {0};
    CHECK(secreq_verdict_v1(&o) == BLERP_VERDICT_INCONCLUSIVE);
    o.linked = true;
    CHECK(secreq_verdict_v1(&o) == BLERP_VERDICT_NO);
    o.pairing_request = true;
    CHECK(secreq_verdict_v1(&o) == BLERP_VERDICT_YES);
}

// V5: the verdict needs the rejected encryption request; a re-pairing after
// it is YES, a disconnect (encryption-failure termination) is NO.
static void test_verdict_v5(void) {
    struct secreq_observation o = {0};
    o.linked = true;
    CHECK(secreq_verdict_v5(&o) == BLERP_VERDICT_INCONCLUSIVE);
    o.enc_rejected = true;
    CHECK(secreq_verdict_v5(&o) == BLERP_VERDICT_NO);
    o.pairing_request = true;
    CHECK(secreq_verdict_v5(&o) == BLERP_VERDICT_YES);
}

// V3: the verdict needs our weaker response; a Central that goes on is YES,
// a Pairing Failed (consistency check) is NO, silence is inconclusive.
static void test_verdict_v3(void) {
    struct secreq_observation o = {0};
    o.linked = true;
    o.pairing_request = true;
    CHECK(secreq_verdict_v3(&o) == BLERP_VERDICT_INCONCLUSIVE);
    o.pairing_response_sent = true;
    CHECK(secreq_verdict_v3(&o) == BLERP_VERDICT_INCONCLUSIVE);
    o.pairing_failed = true;
    o.fail_reason = 0x03;
    CHECK(secreq_verdict_v3(&o) == BLERP_VERDICT_NO);
    o.pairing_failed = false;
    o.central_proceeded = true;
    CHECK(secreq_verdict_v3(&o) == BLERP_VERDICT_YES);
}

int main(void) {
    printf("test_secreq\n");
    test_build_adv_name();
    test_build_adv_no_hid();
    test_build_adv_bad_args();
    test_arpk_guess();
    test_expected_reaction();
    test_classify();
    test_nonconform_apple_case();
    test_conform_cases();
    test_nonconform_session_when_higher();
    test_verdict_v1();
    test_verdict_v5();
    test_verdict_v3();
    return TEST_REPORT();
}
