// ========================================
//  nom du fichier: test_ctkd.c
//  description courte: Unit tests for Cross-Transport Key Derivation (CTKD),
//  h6/h7 crypto functions, and security policy classification.
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "smp/ctkd.h"
#include <string.h>

static void test_h6_h7_crypto(void) {
    uint8_t ltk[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    uint8_t ilk[16];
    uint8_t lk[16];
    memset(ilk, 0, sizeof(ilk));
    memset(lk, 0, sizeof(lk));

    // Test h6 execution
    CHECK(ctkd_h6(ltk, "tmp1", ilk) == 0);
    // Non-zero result
    bool all_zero = true;
    for (int i = 0; i < 16; i++) if (ilk[i] != 0) all_zero = false;
    CHECK(!all_zero);

    CHECK(ctkd_h6(ilk, "lebr", lk) == 0);
    // Intermediate and final LK should differ
    CHECK(memcmp(ilk, lk, 16) != 0);

    // Full LTK -> Link Key derivation (h6)
    uint8_t derived_lk[16];
    CHECK(ctkd_derive_link_key_from_ltk(ltk, false, derived_lk) == 0);
    CHECK(memcmp(derived_lk, lk, 16) == 0);

    // Full LTK -> Link Key derivation (h7 / CT2)
    uint8_t derived_lk_ct2[16];
    CHECK(ctkd_derive_link_key_from_ltk(ltk, true, derived_lk_ct2) == 0);
    // CT2 should produce distinct derivation from non-CT2
    CHECK(memcmp(derived_lk, derived_lk_ct2, 16) != 0);

    // Reverse derivation: Link Key -> LTK
    uint8_t reverse_ltk[16];
    CHECK(ctkd_derive_ltk_from_link_key(lk, false, reverse_ltk) == 0);
    CHECK(memcmp(reverse_ltk, lk, 16) != 0);

    // Null safety
    CHECK(ctkd_h6(NULL, "tmp1", ilk) == -1);
    CHECK(ctkd_h6(ltk, NULL, ilk) == -1);
    CHECK(ctkd_h6(ltk, "tmp1", NULL) == -1);
    CHECK(ctkd_h7(NULL, ltk, ilk) == -1);
    CHECK(ctkd_derive_link_key_from_ltk(NULL, false, lk) == -1);
    CHECK(ctkd_derive_ltk_from_link_key(NULL, false, lk) == -1);
}

static void test_ctkd_classification(void) {
    struct smp_pairing_params req = {
        .io_capability = 0x03,
        .oob_data_flag = 0x00,
        .auth_req = 0x01, // Just Works
        .max_key_size = 16,
        .init_key_dist = 0x0f, // Includes LinkKey 0x08
        .resp_key_dist = 0x0f
    };

    struct smp_pairing_params rsp_stripped = {
        .io_capability = 0x03,
        .auth_req = 0x01,
        .max_key_size = 16,
        .init_key_dist = 0x01,
        .resp_key_dist = 0x01 // Stripped LinkKey bit!
    };

    struct ctkd_report rep;

    // 1. Peer stripped LinkKey: Unsupported
    ctkd_classify_response(&req, &rsp_stripped, NULL, &rep);
    CHECK(!rep.supported);
    CHECK(rep.verdict == CTKD_VERDICT_UNSUPPORTED);

    // 2. Peer accepts LinkKey with unauthenticated Just Works against existing authenticated BR/EDR bond
    struct smp_pairing_params rsp_vuln = {
        .io_capability = 0x03,
        .auth_req = 0x01, // Just Works (MITM=0, SC=0)
        .max_key_size = 16,
        .init_key_dist = 0x09, // EncKey + LinkKey
        .resp_key_dist = 0x09
    };
    struct smp_bond_info bredr_bond = {
        .authenticated = true,
        .enc_size = 16
    };
    ctkd_classify_response(&req, &rsp_vuln, &bredr_bond, &rep);
    CHECK(rep.supported);
    CHECK(rep.verdict == CTKD_VERDICT_VULN_UNAUTH);

    // 3. Peer accepts LinkKey with truncated entropy (e.g. 7 bytes)
    struct smp_pairing_params rsp_entropy = {
        .io_capability = 0x03,
        .auth_req = 0x01,
        .max_key_size = 7, // Truncated!
        .init_key_dist = 0x09,
        .resp_key_dist = 0x09
    };
    ctkd_classify_response(&req, &rsp_entropy, NULL, &rep);
    CHECK(rep.verdict == CTKD_VERDICT_VULN_ENTROPY);

    // 4. Peer enforces authenticated Secure Connections (SC=1, MITM=1, KeySize=16)
    struct smp_pairing_params rsp_protected = {
        .io_capability = 0x04,
        .auth_req = 0x0d, // SC=1, MITM=1, Bonding=1
        .max_key_size = 16,
        .init_key_dist = 0x09,
        .resp_key_dist = 0x09
    };
    ctkd_classify_response(&req, &rsp_protected, &bredr_bond, &rep);
    CHECK(rep.verdict == CTKD_VERDICT_PROTECTED_SC);

    // Labels
    CHECK(strcmp(ctkd_verdict_label(CTKD_VERDICT_UNSUPPORTED), "UNSUPPORTED") == 0);
    CHECK(strcmp(ctkd_verdict_label(CTKD_VERDICT_PROTECTED_SC), "PROTECTED") == 0);
    CHECK(strcmp(ctkd_verdict_label(CTKD_VERDICT_VULN_UNAUTH), "VULN_UNAUTH") == 0);
    CHECK(strcmp(ctkd_verdict_label(CTKD_VERDICT_VULN_ENTROPY), "VULN_ENTROPY") == 0);

    // Null safety
    ctkd_classify_response(NULL, &rsp_protected, NULL, &rep);
    CHECK(rep.verdict == CTKD_VERDICT_UNSUPPORTED);
}

int main(void) {
    printf("test_ctkd\n");
    test_h6_h7_crypto();
    test_ctkd_classification();
    return TEST_REPORT();
}
